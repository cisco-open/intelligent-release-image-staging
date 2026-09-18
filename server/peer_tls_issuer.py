# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Private-swarm certificate issuance over the existing authenticated catalog.

The existing device-pinned catalog certificate authenticates enrollment. A
separate issuing key stays in server tmpfs, with only age ciphertext durable.
Device private keys never leave devices. Caller must authorize the device ID.
"""
import fcntl
import hashlib
import os
from pathlib import Path
import secrets
import subprocess
import tempfile

import secretfs

DAY = 86400


class PeerTLSError(Exception):
    pass


class InvalidCSR(PeerTLSError):
    pass


def mode():
    value = os.environ.get('IRIS_PEER_TLS_MODE', 'disabled')
    if value not in ('disabled', 'required'):
        raise PeerTLSError('invalid peer TLS mode')
    return value


def _openssl(*args, data=None):
    try:
        result = subprocess.run(['openssl', *map(str, args)], input=data,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=15, check=True)
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        raise PeerTLSError('peer certificate operation failed') from None


class Issuer:
    def __init__(self, config=None, runtime=None):
        self.config = Path(config or os.environ.get('IRIS_CONFIG', '/etc/iris')) / 'peer-tls'
        self.runtime = Path(runtime or os.environ.get('IRIS_RUN', '/run/iris')) / 'peer-tls'

    def prepare(self):
        for directory in (self.config, self.runtime):
            if directory.is_symlink():
                raise PeerTLSError('unsafe issuer directory')
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            if directory.stat().st_mode & 0o077:
                raise PeerTLSError('unsafe issuer directory permissions')
        # The deployment-owned parents are not writable by device principals.
        with (self.config / 'issuer.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            encrypted = self.config / 'ca.pem.age'
            bundle = self.runtime / 'ca.pem'
            if any(path.is_symlink() for path in (encrypted, bundle)):
                raise PeerTLSError('unsafe issuer file')
            if bundle.exists() and bundle.stat().st_mode & 0o077:
                raise PeerTLSError('unsafe issuer key permissions')
            if encrypted.exists():
                if not bundle.exists():
                    secretfs.decrypt_to(str(encrypted), str(bundle),
                                        os.environ['IRIS_AGE_KEY_FILE'])
            elif bundle.exists():
                raise PeerTLSError('peer CA has no durable ciphertext')
            else:
                with tempfile.TemporaryDirectory(dir=str(self.runtime)) as tmp:
                    key, cert = Path(tmp) / 'key.pem', Path(tmp) / 'cert.pem'
                    _openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt',
                             'ec_paramgen_curve:prime256v1', '-nodes', '-sha256',
                             '-days', '3650', '-subj', '/CN=IRIS Private Swarm CA',
                             '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
                             '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
                             '-keyout', key, '-out', cert)
                    pending = Path(tmp) / 'ca.pem'
                    pending.write_bytes(cert.read_bytes() + key.read_bytes())
                    pending.chmod(0o600)
                    secretfs.encrypt_from(str(pending), str(encrypted),
                                          os.environ.get('IRIS_AGE_RECIPIENTS', ''))
                    os.replace(str(pending), str(bundle))
            _openssl('x509', '-in', bundle, '-checkend', str(2 * DAY), '-noout')
            return bundle

    def issue(self, device_id, csr):
        if not isinstance(csr, str) or not 1 <= len(csr) <= 8192:
            raise InvalidCSR('invalid certificate request')
        try:
            data = csr.encode('ascii')
        except UnicodeEncodeError:
            raise InvalidCSR('invalid certificate request') from None
        # Never honor CSR extensions or subject names supplied by the caller.
        try:
            _openssl('req', '-verify', '-noout', data=data)
            public = _openssl('req', '-pubkey', '-noout', data=data)
            description = _openssl('pkey', '-pubin', '-text', '-noout', data=public)
        except PeerTLSError:
            raise InvalidCSR('invalid certificate request') from None
        if b'ASN1 OID: prime256v1' not in description:
            raise InvalidCSR('P-256 node key required')
        bundle = self.prepare()
        identity = hashlib.sha256(device_id.encode('utf-8')).hexdigest()
        with tempfile.TemporaryDirectory(dir=str(self.runtime)) as tmp:
            extensions = Path(tmp) / 'extensions'
            extensions.write_text('basicConstraints=critical,CA:FALSE\n'
                                  'keyUsage=critical,digitalSignature\n'
                                  'extendedKeyUsage=serverAuth,clientAuth\n'
                                  'subjectAltName=URI:urn:iris:device:' + identity + '\n')
            cert = _openssl('x509', '-req', '-CA', bundle, '-CAkey', bundle,
                            '-set_serial', '0x' + secrets.token_hex(19),
                            '-days', '1', '-sha256', '-subj', '/CN=' + identity,
                            '-extfile', extensions, data=data)
        ca = _openssl('x509', '-in', bundle, '-outform', 'PEM')
        return {'mode': 'required', 'certificate': cert.decode('ascii'),
                'ca': ca.decode('ascii'), 'renew_before_seconds': 21600}
