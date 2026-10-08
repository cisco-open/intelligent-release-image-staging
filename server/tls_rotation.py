# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Console TLS key generation, public approval and recoverable publication.

Private candidates persist only as age ciphertext. Approval is bound to one
request and exact SAN set. Publication repairs only old-or-approved file bytes;
it cannot overwrite a concurrent administrator's unrelated certificate.
"""

import base64
from contextlib import contextmanager
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
import time
import uuid

import gui_tls
import instruction_keys as keys
import secretfs
import trust

STATES = ('idle', 'awaiting-approval', 'approved', 'committing', 'published', 'cancelled')
PUBLIC = ('request_id', 'state', 'names', 'mode', 'csr', 'certificate', 'created_at', 'fingerprint_sha256')


class RotationError(ValueError):
    pass


def journal_path():
    return Path(os.environ.get('IRIS_CONFIG', '/etc/iris')) / 'tls' / 'rotation.json'


def _read(path):
    if not keys._path_exists(path, 'TLS rotation file unavailable'):
        return None
    return keys._read_regular(path, 256 * 1024, unavailable='TLS rotation file unavailable', too_large='TLS rotation file oversized')


def _sha(data):
    return hashlib.sha256(data).hexdigest() if data is not None else None


def _paths():
    return [Path(gui_tls._durable_key_path()), Path(gui_tls._durable_crt_path()), Path(gui_tls.combined_path())]


def _openssl(*args, data=None):
    try:
        return subprocess.run(['openssl', *map(str, args)], input=data, capture_output=True, timeout=30, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        raise RotationError('Certificate operation failed; check the public request and approval') from None


def _names(values):
    if not isinstance(values, list) or not 1 <= len(values) <= 16:
        raise RotationError('Provide 1–16 exact DNS names or IP addresses')
    result = []
    for value in values:
        if not isinstance(value, str) or not 1 <= len(value) <= 253:
            raise RotationError('Invalid certificate name')
        try:
            name = str(ipaddress.ip_address(value))
        except ValueError:
            name = value.lower()
            if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', name) or any(
                    not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in name.split('.')):
                raise RotationError('Use exact DNS names or IP addresses, without wildcards or URLs')
        if name in result:
            raise RotationError('Certificate names must be distinct')
        result.append(name)
    return sorted(result)


def _id(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError()
    except ValueError:
        raise RotationError('Use a canonical request ID') from None


def _load():
    raw = _read(journal_path())
    if raw is None:
        return None
    record = keys._strict_json_loads(raw, 'TLS rotation journal')
    if (not isinstance(record, dict) or set(record) != set(PUBLIC) | {'schema', 'ciphertext', 'before'}
            or type(record['schema']) is not int or record['schema'] != 1
            or not isinstance(record['state'], str) or record['state'] not in STATES[1:]
            or record['mode'] not in ('ca', 'self-signed')
            or type(record['created_at']) is not int or record['created_at'] < 0
            or not isinstance(record['before'], list) or len(record['before']) != 3
            or not isinstance(record['csr'], str) or len(record['csr']) > 16384
            or record['certificate'] is not None and (not isinstance(record['certificate'], str) or len(record['certificate']) > 65536)):
        raise RotationError('TLS rotation journal is invalid; preserve it for recovery')
    _id(record['request_id'])
    if _names(record['names']) != record['names']:
        raise RotationError('Invalid names in TLS rotation journal')
    for digest in [*record['before'], record['fingerprint_sha256']]:
        if digest is not None and (not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)):
            raise RotationError('Invalid TLS rotation fingerprint')
    if record['state'] in ('awaiting-approval', 'approved', 'committing'):
        _ciphertext(record)
    elif record['ciphertext'] is not None:
        raise RotationError('Finished TLS rotation retained candidate ciphertext')
    return record


def _ciphertext(record):
    try:
        raw = base64.b64decode(record['ciphertext'], validate=True)
        if not 1 <= len(raw) <= 65536 or not raw.startswith(b'age-encryption.org/v1'):
            raise ValueError()
        return raw
    except (ValueError, TypeError):
        raise RotationError('Invalid encrypted TLS candidate') from None


def _save(record):
    keys._atomic_write_json(journal_path(), record)


def _view(record):
    if record is None:
        return dict(request_id=None, state='idle', names=[], mode=None, csr=None,
                    certificate=None, created_at=None, fingerprint_sha256=None)
    return {name: record[name] for name in PUBLIC}


@contextmanager
def _runtime():
    # Match signing custody: private temporary material stays in the configured
    # private runtime directory, mounted tmpfs by supported deployments.
    root = keys._runtime_directory(keys.InstructionPaths.from_env())
    if Path(root).is_symlink() or Path(root).stat().st_mode & 0o077:
        raise RotationError('TLS candidate runtime directory must be private')
    with tempfile.TemporaryDirectory(prefix='.tls-rotation-', dir=root) as directory:
        yield Path(directory)


@contextmanager
def _material(record):
    with _runtime() as directory:
        cipher, private = directory / 'candidate.age', directory / 'candidate.key'
        keys._atomic_write(cipher, _ciphertext(record))
        secretfs.decrypt_to(str(cipher), str(private), os.environ.get('IRIS_AGE_KEY_FILE', '/run/secrets/iris_age_key'))
        # Verify the journal's public CSR is tied to this candidate key.
        csr_public = _openssl('req', '-pubkey', '-noout', data=record['csr'].encode('ascii'))
        if csr_public != _openssl('pkey', '-in', private, '-pubout'):
            raise RotationError('TLS candidate does not match its public request')
        yield private


def _validate_certificate(record, certificate, private, *, admission=True):
    if not isinstance(certificate, str) or len(certificate) > 65536 or 'PRIVATE KEY' in certificate:
        raise RotationError('Import only the approved public certificate chain')
    blocks = trust.split_pem_certs(certificate)
    if not blocks or len(blocks) > 8:
        raise RotationError('Import a bounded PEM certificate chain, leaf first')
    normalized = '\n'.join(blocks) + '\n'
    if gui_tls.validate_pair(normalized, private.read_text()) is not None:
        raise RotationError('Certificate does not match this replacement key')
    with _runtime() as directory:
        leaf = directory / 'leaf.pem'
        keys._atomic_write(leaf, blocks[0].encode('ascii'))
        info = ssl._ssl._test_decode_cert(str(leaf))
        now = time.time()
        if admission and (ssl.cert_time_to_seconds(info['notBefore']) > now or ssl.cert_time_to_seconds(info['notAfter']) <= now + 7 * 86400):
            raise RotationError('Certificate must be valid now with more than seven days remaining')
        names = [value for kind, value in info.get('subjectAltName', ()) if kind in ('DNS', 'IP Address')]
        if _names(names) != record['names'] or len(info.get('subjectAltName', ())) != len(names):
            raise RotationError('Approved certificate names must exactly match the request')
        purpose = _openssl('x509', '-in', leaf, '-purpose', '-noout')
        if b'SSL server : Yes' not in purpose:
            raise RotationError('Certificate must permit TLS server authentication')
    return normalized, _sha(ssl.PEM_cert_to_DER_cert(blocks[0]))


def status():
    with gui_tls.rotation_lock():
        return _view(_load())


def operate(payload):
    if not isinstance(payload, dict):
        raise RotationError('Expected one TLS rotation action')
    action = payload.get('action')
    fields = {'prepare': {'names', 'mode'}, 'approve': {'certificate'}, 'apply': {'confirm'}, 'cancel': set()}
    if not isinstance(action, str) or action not in fields or set(payload) != {'action', 'request_id'} | fields[action]:
        raise RotationError('Unexpected TLS rotation fields')
    _id(payload['request_id'])
    with gui_tls.rotation_lock():
        record = _load()
        if action == 'prepare':
            names = _names(payload['names'])
            if payload['mode'] not in ('ca', 'self-signed'):
                raise RotationError('Choose CA approval or an explicit self-signed replacement')
            if record and record['request_id'] == payload['request_id']:
                if record['names'] != names or record['mode'] != payload['mode']:
                    raise RotationError('Request ID belongs to different certificate parameters')
                return _view(record)
            if record and record['state'] not in ('published', 'cancelled'):
                raise RotationError('Finish or cancel the pending TLS rotation')
            if not os.environ.get('IRIS_AGE_RECIPIENTS'):
                raise RotationError('Durable encrypted key storage must be configured')
            with _runtime() as directory:
                private, cipher = directory / 'candidate.key', directory / 'candidate.age'
                _openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', private)
                private.chmod(0o600)
                sans = []
                for name in names:
                    try:
                        ipaddress.ip_address(name)
                        sans.append('IP:' + name)
                    except ValueError:
                        sans.append('DNS:' + name)
                extensions = ['-subj', '/CN=IRIS Console', '-addext', 'subjectAltName=' + ','.join(sans),
                              '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'extendedKeyUsage=serverAuth']
                csr = _openssl('req', '-new', '-key', private, *extensions).decode('ascii')
                secretfs.encrypt_from(str(private), str(cipher), os.environ['IRIS_AGE_RECIPIENTS'])
                record = dict(schema=1, request_id=payload['request_id'], state='awaiting-approval', names=names,
                    mode=payload['mode'], csr=csr, certificate=None, created_at=int(time.time()), fingerprint_sha256=None,
                    ciphertext=base64.b64encode(cipher.read_bytes()).decode('ascii'), before=[_sha(_read(p)) for p in _paths()])
                # Prove runtime identity recovery before publishing the request.
                with _material(record):
                    pass
                if payload['mode'] == 'self-signed':
                    certificate = _openssl('req', '-x509', '-new', '-key', private, '-days', '90', *extensions).decode('ascii')
                    record['certificate'], record['fingerprint_sha256'] = _validate_certificate(record, certificate, private)
                    record['state'] = 'approved'
                _save(record)
        else:
            if not record or record['request_id'] != payload['request_id']:
                raise RotationError('TLS request changed; refresh before continuing')
            if action == 'cancel':
                if record['state'] not in ('awaiting-approval', 'approved', 'cancelled'):
                    raise RotationError('An admitted TLS change cannot be cancelled')
                record.update(state='cancelled', ciphertext=None)
                _save(record)
            elif action == 'approve':
                if record['state'] not in ('awaiting-approval', 'approved'):
                    raise RotationError('This TLS request no longer accepts approval')
                with _material(record) as private:
                    certificate, digest = _validate_certificate(record, payload['certificate'], private)
                record.update(state='approved', certificate=certificate, fingerprint_sha256=digest)
                _save(record)
            elif action == 'apply':
                if payload['confirm'] is not True or record['state'] not in ('approved', 'committing', 'published'):
                    raise RotationError('Confirm an approved TLS replacement')
                if record['state'] == 'published':
                    if gui_tls.active_info()['fingerprint_sha256'].replace(':', '').lower() != record['fingerprint_sha256']:
                        raise RotationError('Active certificate changed after this publication')
                    return _view(record)
                with _material(record) as private:
                    # Completing an admitted write repairs the exact approved
                    # bytes, not a new validity decision. Elapsed time must not
                    # strand a partially published pair. An expired result
                    # still needs renewal; recovery is not renewal evidence.
                    recovering = record['state'] == 'committing'
                    cert, digest = _validate_certificate(record, record['certificate'], private, admission=not recovering)
                    if digest != record['fingerprint_sha256']:
                        raise RotationError('TLS approval changed')
                    outputs = [_ciphertext(record), cert.encode('ascii'), cert.encode('ascii') + private.read_bytes()]
                    current = [_sha(_read(p)) for p in _paths()]
                    if any(value not in (old, _sha(new)) and not (recovering and index == 2 and value is None)
                           for index, (value, old, new) in enumerate(zip(current, record['before'], outputs))):
                        raise RotationError('TLS files changed outside this request; do not overwrite them')
                    if record['state'] == 'approved' and current != record['before']:
                        raise RotationError('TLS files changed before publication')
                    record['state'] = 'committing'
                    _save(record)
                    for path, content in zip(_paths(), outputs):
                        keys._atomic_write(path, content)
                    record.update(state='published', ciphertext=None)
                    _save(record)
        return _view(record)
