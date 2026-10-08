# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Deployment-bound mutual TLS for a worker outside a Kubernetes cluster."""

import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import stat
import tempfile
import threading
from socketserver import ThreadingMixIn
from urllib.parse import urlsplit

from .state import InstallError, atomic_write, regular_bytes


def endpoint(value):
    try:
        if not isinstance(value, str) or any(ord(char) < 33 or ord(char) == 127 for char in value):
            raise ValueError()
        parsed = urlsplit(value)
        host, port = parsed.hostname, parsed.port
        if (parsed.scheme != 'https' or not host or port is None
                or parsed.username is not None or parsed.password is not None
                or parsed.path not in ('', '/') or parsed.query or parsed.fragment
                or not 1024 <= port <= 65535):
            raise ValueError()
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                                          for label in host.split('.')):
                raise ValueError()
        else:
            if address.version != 4 or address.is_unspecified or address.is_multicast:
                raise ValueError()
        return host, port
    except (ValueError, TypeError, AttributeError):
        raise InstallError('Worker URL must be an explicit HTTPS host and port without credentials or a path') from None


def _private(path):
    path = Path(path)
    info = path.lstat()
    if (path.resolve() != path or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077):
        raise InstallError('Unsafe lifecycle transport private key')


def prepare_network_custody(base, url, runner):
    """Generate once; a partial/existing identity is verified, never replaced.

    Only ca.crt, client.crt and client.key belong in the SERVER pod Secret.
    The worker and CA private keys remain in this protected host directory.
    """
    host, _port = endpoint(url)
    directory = Path(base).absolute() / 'lifecycle-tls'
    names = ('ca.crt', 'ca.key', 'worker.crt', 'worker.key', 'client.crt', 'client.key')
    if not directory.exists() and not directory.is_symlink():
        # Publish complete custody with a single rename. Interrupted scratch is
        # not an authority and cannot be mistaken for an existing identity.
        with tempfile.TemporaryDirectory(prefix='lifecycle-tls-', dir=base) as temporary:
            scratch = Path(temporary)
            runner(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-days', '1095',
                    '-subj', '/CN=IRIS lifecycle transport CA', '-keyout', str(scratch / 'ca.key'),
                    '-out', str(scratch / 'ca.crt'), '-addext', 'basicConstraints=critical,CA:TRUE',
                    '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
            try:
                ipaddress.ip_address(host)
                san = 'IP:' + host
            except ValueError:
                san = 'DNS:' + host
            for role, usage in (('worker', 'serverAuth'), ('client', 'clientAuth')):
                runner(['openssl', 'req', '-new', '-newkey', 'rsa:3072', '-nodes',
                        '-subj', '/CN=iris-lifecycle-' + role, '-keyout', str(scratch / (role + '.key')),
                        '-out', str(scratch / (role + '.csr'))])
                extension = 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=' + usage + '\n'
                if role == 'worker':
                    extension += 'subjectAltName=' + san + '\n'
                atomic_write(scratch / 'extensions', extension.encode())
                runner(['openssl', 'x509', '-req', '-in', str(scratch / (role + '.csr')),
                        '-CA', str(scratch / 'ca.crt'), '-CAkey', str(scratch / 'ca.key'),
                        '-set_serial', '1' if role == 'worker' else '2', '-days', '397',
                        '-extfile', str(scratch / 'extensions'), '-out', str(scratch / (role + '.crt'))])
            ready = scratch / 'ready'
            ready.mkdir(mode=0o700)
            for name in names:
                atomic_write(ready / name, regular_bytes(scratch / name, 16384), 0o600 if name.endswith('.key') else 0o644)
            atomic_write(ready / 'endpoint.json', json.dumps({'url': url}).encode())
            os.rename(ready, directory)
            fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    info = directory.lstat()
    if (directory.resolve() != directory or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700
            or set(p.name for p in directory.iterdir()) != set(names) | {'endpoint.json'}):
        raise InstallError('Incomplete or unsafe lifecycle transport custody; preserve it for recovery')
    if json.loads(regular_bytes(directory / 'endpoint.json')) != {'url': url}:
        raise InstallError('Lifecycle endpoint changed outside its approved deployment')
    for role in ('ca', 'worker', 'client'):
        _private(directory / (role + '.key'))
        public = runner(['openssl', 'pkey', '-in', str(directory / (role + '.key')), '-pubout'], capture=True)
        certificate = runner(['openssl', 'x509', '-in', str(directory / (role + '.crt')), '-pubkey', '-noout'], capture=True)
        if public != certificate:
            raise InstallError('Lifecycle certificate does not match its retained key')
    for role, purpose in (('worker', 'sslserver'), ('client', 'sslclient')):
        identity = []
        if role == 'worker':
            try:
                ipaddress.ip_address(host)
                identity = ['-verify_ip', host]
            except ValueError:
                identity = ['-verify_hostname', host]
        runner(['openssl', 'verify', '-CAfile', str(directory / 'ca.crt'), '-purpose', purpose,
                *identity, str(directory / (role + '.crt'))])
        runner(['openssl', 'x509', '-checkend', '604800', '-noout', '-in', str(directory / (role + '.crt'))])
    return {name: directory / name for name in names}


def _transport(custody, extra_client_digests=()):
    """Build replacement context completely before publishing it to listeners."""
    for name in ('worker.key', 'client.key'):
        _private(custody[name])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(custody['worker.crt']), str(custody['worker.key']))
    context.load_verify_locations(cafile=str(custody['ca.crt']))
    context.verify_mode = ssl.CERT_REQUIRED
    client_der = ssl.PEM_cert_to_DER_cert(regular_bytes(custody['client.crt'], 16384).decode())
    expected = hashlib.sha256(client_der).digest()
    if any(not isinstance(value, bytes) or len(value) != 32 for value in extra_client_digests):
        raise InstallError('Invalid client certificate overlap')
    return context, frozenset((expected, *extra_client_digests))


def make_https_server(bind, port, worker, custody):
    """Only a pinned server-tier client certificate may send bounded RPC."""
    initial_transport = _transport(custody)

    class Server(ThreadingMixIn, HTTPServer):
        daemon_threads = True

        def __init__(self, *args):
            self.transport = initial_transport
            self.connections = threading.BoundedSemaphore(8)
            super().__init__(*args)

        def configure_transport(self, custody, extra_client_digests=()):
            self.transport = _transport(custody, extra_client_digests)

        def process_request(self, request, client_address):
            if not self.connections.acquire(blocking=False):
                self.shutdown_request(request)
                return
            try:
                super().process_request(request, client_address)
            except BaseException:
                self.connections.release()
                raise

        def process_request_thread(self, request, client_address):
            secure = None
            try:
                request.settimeout(5)
                active_context, permitted = self.transport
                secure = active_context.wrap_socket(request, server_side=True)
                if hashlib.sha256(secure.getpeercert(binary_form=True)).digest() not in permitted:
                    return
                self.finish_request(secure, client_address)
            except Exception:
                # Worker/runtime errors must not produce a thread traceback
                # containing private filesystem or subprocess diagnostics.
                pass
            finally:
                self.shutdown_request(secure if secure is not None else request)
                self.connections.release()

        def handle_error(self, request, client_address):
            # Socket/parser failures must not disclose headers or key material.
            pass

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            try:
                length = self.headers.get_all('Content-Length', [])
                if (self.path != '/v1/lifecycle' or self.headers.get('Transfer-Encoding') is not None
                        or len(length) != 1 or not length[0].isdigit() or not 1 <= int(length[0]) <= 4096):
                    raise ValueError()
                raw = self.rfile.read(int(length[0]))
                if len(raw) != int(length[0]):
                    raise ValueError()
                request = json.loads(raw)
                if not isinstance(request, dict):
                    raise ValueError()
                if request.get('action') in ('transport-status', 'renew-transport', 'recover-transport'):
                    raise ValueError('Host-only action')
                if request.get('action') == 'transport-proof':
                    if set(request) != {'action', 'request_id'} or not hasattr(worker, 'transport_proof'):
                        raise ValueError('Invalid transport proof')
                    peer = hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()
                    result = worker.transport_proof(request, peer)
                else:
                    result = (worker.status() if request == {'action': 'status'} else
                              worker.deployment_info() if request == {'action': 'deployment-info'} else
                              worker.rotation_status() if request == {'action': 'rotation-status'} else worker.submit(request))
                response = {'ok': True, 'result': result}
                status = 200
            except (InstallError, ValueError, TypeError):
                response = {'ok': False, 'error': 'Maintenance request refused; inspect the protected host journal.'}
                status = 400
            except Exception:
                response = {'ok': False, 'error': 'Maintenance service unavailable; inspect the protected host journal.'}
                status = 500
            encoded = json.dumps(response).encode() + b'\n'
            if len(encoded) > 128 * 1024:
                encoded = b'{"ok":false,"error":"Maintenance evidence exceeds the response limit"}\n'
                status = 500
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(encoded)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(encoded)
            self.close_connection = True

    return Server((bind, port), Handler)
