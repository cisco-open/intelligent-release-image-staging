# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Journalled online signer replacement; offline roots and replay state stay put.

The custody lock serializes the journal and signing. An approved commit is a
roll-forward intent, repaired before any later custody operation can sign. Only
encrypted candidate keys and public evidence are durable. Retirement requires
an independently root-signed KRL, not merely deletion of the former private key.
"""

import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import uuid

import instruction_keys as keys

SCHEMA = 'iris-online-rotation/v1'
STATES = {'awaiting-approval', 'committing', 'retirement-pending', 'retiring', 'completed', 'cancelled'}
FIELDS = {'schema', 'id', 'state', 'created_at', 'old_public', 'new_public',
          'old_cert_sha', 'old_cipher_sha', 'roots_sha', 'ciphertext', 'certificate',
          'approved_at', 'retirement_payload', 'retirement_base', 'retired_seq'}


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _file(path, limit=keys.MAX_KEYLIST_BYTES):
    return keys._read_regular(path, limit, unavailable='rotation material unavailable',
                              too_large='rotation material exceeds its limit')


def _path(paths):
    return Path(paths.config_dir) / 'instr/online-rotation.json'


def _decode(value, limit):
    try:
        if not isinstance(value, str) or len(value) > 4 * ((limit + 2) // 3):
            raise ValueError()
        raw = base64.b64decode(value, validate=True)
        if len(raw) > limit:
            raise ValueError()
        return raw
    except ValueError:
        raise keys.InstructionKeyError('invalid rotation public artifact') from None


def _id(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError()
    except ValueError:
        raise keys.InstructionKeyError('provide a canonical rotation request ID') from None
    return value


def _load(paths):
    if not keys._path_exists(_path(paths), 'rotation journal unavailable'):
        return None
    value = keys._strict_json_loads(_file(_path(paths), 512 * 1024), 'rotation journal')
    if (not isinstance(value, dict) or set(value) != FIELDS or value['schema'] != SCHEMA
            or not isinstance(value['state'], str) or value['state'] not in STATES
            or not keys._is_int(value['created_at'])):
        raise keys.InstructionKeyError('rotation journal is invalid; do not reset it')
    _id(value['id'])
    for name in ('old_public', 'new_public'):
        if not isinstance(value[name], str) or not value[name].isascii():
            raise keys.InstructionKeyError('rotation public key is invalid')
        keys._public_key_bytes(value[name].encode('ascii'), message='rotation public key')
    for name in ('old_cert_sha', 'old_cipher_sha', 'roots_sha'):
        if not isinstance(value[name], str) or not keys._SHA256.fullmatch(value[name]):
            raise keys.InstructionKeyError('rotation journal digest is invalid')
    if (value['retirement_base'] is not None and (not isinstance(value['retirement_base'], str)
            or not keys._SHA256.fullmatch(value['retirement_base']))):
        raise keys.InstructionKeyError('rotation keylist baseline is invalid')
    if value['retirement_payload'] is not None:
        keys._parse_keylist_payload(_decode(value['retirement_payload'], keys.MAX_KEYLIST_PAYLOAD_BYTES))
    if value['retired_seq'] is not None and not keys._is_int(value['retired_seq'], minimum=1):
        raise keys.InstructionKeyError('rotation retirement sequence is invalid')
    if value['state'] in ('awaiting-approval', 'committing'):
        if not _decode(value['ciphertext'], keys.MAX_KEYLIST_BYTES):
            raise keys.InstructionKeyError('rotation ciphertext is missing')
    elif value['ciphertext'] is not None:
        raise keys.InstructionKeyError('completed key switch retained candidate ciphertext')
    if value['state'] in ('committing', 'retirement-pending', 'retiring', 'completed'):
        if (not keys._is_int(value['approved_at']) or not isinstance(value['certificate'], str)
                or not value['certificate'].isascii()
                or len(value['certificate']) > keys.MAX_CERTIFICATE_BYTES):
            raise keys.InstructionKeyError('rotation approval is invalid')
    elif value['approved_at'] is not None or value['certificate'] is not None:
        raise keys.InstructionKeyError('unapproved rotation contains approval state')
    if value['state'] in ('retiring', 'completed') and value['retirement_payload'] is None:
        raise keys.InstructionKeyError('rotation retirement request is missing')
    if (value['state'] == 'completed') != (value['retired_seq'] is not None):
        raise keys.InstructionKeyError('rotation retirement receipt is inconsistent')
    return value


def _save(paths, record):
    keys._atomic_write_json(_path(paths), record)


def _roots(paths):
    return keys.discover_roots(paths)


def _roots_sha(roots):
    return _sha(json.dumps({name: _sha(blob) for name, blob in roots.items()}, sort_keys=True).encode())


def _view(record, roots):
    return {'state': record['state'] if record else 'idle',
            'request_id': record['id'] if record else None,
            'previous_public_key': record['old_public'] if record else None,
            'public_key': record['new_public'] if record else None,
            'previous_sha256': _sha(record['old_public'].encode()) if record else None,
            'replacement_sha256': _sha(record['new_public'].encode()) if record else None,
            'created_at': record['created_at'] if record else None,
            'activated_at': record['approved_at'] if record else None,
            'retired_keylist_seq': record['retired_seq'] if record else None,
            'root_ids': sorted(roots),
            'note': 'Server-side evidence only; device acceptance is checked separately. Offline private roots stay with their custodians.'}


def status(paths=None):
    paths = paths or keys.InstructionPaths.from_env()
    with keys._custody_lock(paths):
        return _view(_load(paths), _roots(paths))


def _require(record, request_id):
    if record is None or record['id'] != _id(request_id):
        raise keys.InstructionKeyError('rotation request changed; refresh before continuing')


@contextmanager
def _material(paths, record):
    with tempfile.TemporaryDirectory(prefix='.rotation-check-', dir=keys._runtime_directory(paths)) as directory:
        encrypted, plain = Path(directory) / 'candidate.age', Path(directory) / 'signing-key'
        keys._atomic_write(encrypted, _decode(record['ciphertext'], keys.MAX_KEYLIST_BYTES))
        keys._default_decrypt(encrypted, plain, os.environ.get('IRIS_AGE_KEY_FILE', '/run/secrets/iris_age_key'))
        private = _file(plain, keys.MAX_PRIVATE_KEY_BYTES)
        public = keys._derive_public_bytes(paths, private, timeout=keys.SSH_TIMEOUT, ssh_keygen='ssh-keygen')
        if public.decode('ascii') != record['new_public']:
            raise keys.InstructionKeyError('candidate key does not match its public request')
        yield private, public


def prepare(request_id, *, paths=None, now=None):
    request_id = _id(request_id)
    paths = paths or keys.InstructionPaths.from_env()
    now = int(time.time()) if now is None else now
    with keys._custody_lock(paths):
        current = _load(paths)
        roots = _roots(paths)
        if current and current['id'] == request_id:
            return _view(current, roots)
        if current and current['state'] not in ('completed', 'cancelled'):
            raise keys.InstructionKeyError('finish or cancel the existing rotation first')
        _private, public = keys._ensure_runtime_key_locked(paths, required=True)
        certificate = _file(paths.certificate, keys.MAX_CERTIFICATE_BYTES)
        ciphertext = _file(paths.encrypted_key)
        # Reuse key generation/recovery proof, but only inside disposable tmpfs.
        with tempfile.TemporaryDirectory(prefix='.rotation-prepare-', dir=keys._runtime_directory(paths)) as directory:
            candidate = keys.InstructionPaths(str(Path(directory) / 'state'),
                str(Path(directory) / 'config'), str(Path(directory) / 'run'))
            keys._generate_online_key_locked(candidate, os.environ.get('IRIS_AGE_RECIPIENTS', ''),
                identity_file=None, encrypt_fn=None, decrypt_fn=None,
                timeout=keys.SSH_TIMEOUT, ssh_keygen='ssh-keygen')
            record = dict(schema=SCHEMA, id=request_id, state='awaiting-approval', created_at=now,
                old_public=public.decode('ascii'), new_public=_file(candidate.public_key).decode('ascii'),
                old_cert_sha=_sha(certificate), old_cipher_sha=_sha(ciphertext), roots_sha=_roots_sha(roots),
                ciphertext=base64.b64encode(_file(candidate.encrypted_key)).decode(), certificate=None,
                approved_at=None, retirement_payload=None, retirement_base=None, retired_seq=None)
            _save(paths, record)
        return _view(record, roots)


def recover_locked(paths):
    """Called by the custody lock BEFORE admitting any signing/import operation."""
    record = _load(paths)
    if record is None or record['state'] != 'committing':
        return
    roots = _roots(paths)
    if _roots_sha(roots) != record['roots_sha']:
        raise keys.InstructionKeyError('rotation trust changed; resolve custody before signing')
    certificate = record['certificate'].encode('ascii')
    ciphertext = _decode(record['ciphertext'], keys.MAX_KEYLIST_BYTES)
    public = record['new_public'].encode('ascii')
    # Any partially published tuple must consist ONLY of old or approved bytes.
    for path, before, after in ((paths.encrypted_key, record['old_cipher_sha'], _sha(ciphertext)),
                               (paths.public_key, _sha(record['old_public'].encode()), _sha(public)),
                               (paths.certificate, record['old_cert_sha'], _sha(certificate))):
        if _sha(_file(path)) not in (before, after):
            raise keys.InstructionKeyError('rotation authority changed; refusing to overwrite it')
    with _material(paths, record) as (private, public):
        # Finish the already-approved transaction at its approval time. If it
        # expired during an outage, normal signing still refuses it afterward.
        krl = keys._installed_krl_locked(paths, roots, timeout=keys.SSH_TIMEOUT, ssh_keygen='ssh-keygen')
        keys._certificate_operation_locked(paths, private, public, certificate, roots,
            now=record['approved_at'], krl=krl, body=None, timeout=keys.SSH_TIMEOUT, ssh_keygen='ssh-keygen')
        for path, content, mode in ((paths.encrypted_key, ciphertext, 0o600),
                (paths.public_key, public, 0o644), (paths.certificate, certificate, 0o644),
                (paths.runtime_key, private, 0o600), (paths.runtime_key + '.pub', public, 0o644),
                (paths.runtime_certificate, certificate, 0o644)):
            keys._atomic_write(path, content, mode=mode)
    record.update(state='retirement-pending', ciphertext=None)
    _save(paths, record)


def activate(request_id, certificate, *, paths=None, now=None):
    paths = paths or keys.InstructionPaths.from_env()
    now = int(time.time()) if now is None else now
    if (not isinstance(certificate, str) or not certificate.isascii() or len(certificate) > keys.MAX_CERTIFICATE_BYTES
            or not certificate.startswith('ssh-ed25519-cert-v01@openssh.com ')
            or len(certificate.strip().splitlines()) != 1):
        raise keys.InstructionKeyError('return one public certificate, never a private key')
    with keys._custody_lock(paths):
        record = _load(paths)
        _require(record, request_id)
        roots = _roots(paths)
        if record['state'] in ('retirement-pending', 'retiring', 'completed'):
            if record['certificate'] != certificate:
                raise keys.InstructionKeyError('rotation already applied with a different approval')
            return _view(record, roots)
        if record['state'] != 'awaiting-approval':
            raise keys.InstructionKeyError('rotation is not awaiting approval')
        if (_roots_sha(roots) != record['roots_sha']
                or _sha(_file(paths.certificate)) != record['old_cert_sha']
                or _sha(_file(paths.encrypted_key)) != record['old_cipher_sha']
                or _file(paths.public_key).decode('ascii') != record['old_public']):
            raise keys.InstructionKeyError('current custody changed; cancel and prepare rotation again')
        with _material(paths, record) as (private, public):
            krl = keys._installed_krl_locked(paths, roots, timeout=keys.SSH_TIMEOUT, ssh_keygen='ssh-keygen')
            info, _ = keys._certificate_operation_locked(paths, private, public, certificate.encode('ascii'), roots,
                now=now, krl=krl, body=None, timeout=keys.SSH_TIMEOUT, ssh_keygen='ssh-keygen')
            if info['valid_before'] - now <= keys.CERTIFICATE_REFUSE_SECONDS:
                raise keys.InstructionKeyError('replacement certificate needs more than seven days remaining')
        record.update(state='committing', certificate=certificate, approved_at=now)
        _save(paths, record)  # Durable roll-forward boundary; never revert afterward.
        recover_locked(paths)
        return _view(_load(paths), roots)


def cancel(request_id, *, paths=None):
    paths = paths or keys.InstructionPaths.from_env()
    with keys._custody_lock(paths):
        record = _load(paths)
        _require(record, request_id)
        if record['state'] not in ('awaiting-approval', 'cancelled'):
            raise keys.InstructionKeyError('an activated rotation cannot be cancelled')
        record.update(state='cancelled', ciphertext=None)
        _save(paths, record)
        return _view(record, _roots(paths))


def retirement_request(request_id, root_id, *, paths=None, now=None):
    paths = paths or keys.InstructionPaths.from_env()
    now = int(time.time()) if now is None else now
    with keys._custody_lock(paths):
        record = _load(paths)
        _require(record, request_id)
        roots = _roots(paths)
        if record['state'] not in ('retirement-pending', 'retiring') or root_id not in roots:
            raise keys.InstructionKeyError('choose a configured root for the pending retirement')
        if _file(paths.public_key).decode('ascii') != record['new_public']:
            raise keys.InstructionKeyError('active signer changed; review custody before retirement')
        snapshot = keys._load_keylist_snapshot_locked(paths)
        if snapshot and not snapshot['metadata_consistent']:
            raise keys.InstructionKeyError('repair the installed keylist before retirement')
        baseline = snapshot['parsed']['artifact_sha256'] if snapshot else None
        if record['retirement_payload'] and record['retirement_base'] == baseline:
            raw = _decode(record['retirement_payload'], keys.MAX_KEYLIST_PAYLOAD_BYTES)
            metadata, _ = keys._parse_keylist_payload(raw)
            if metadata['signer_root_id'] == root_id:
                return {'request_id': record['id'], 'payload': record['retirement_payload'], 'root_id': root_id}
        with tempfile.TemporaryDirectory(dir=keys._runtime_directory(paths)) as directory:
            old = Path(directory) / 'former.pub'
            krl = Path(directory) / 'revocations.krl'
            keys._atomic_write(old, record['old_public'].encode())
            command = ['-k', '-f', str(krl)]
            if snapshot:
                keys._atomic_write(krl, snapshot['parsed']['krl'])
                command.append('-u')
            keys._run_ssh(command + [str(old)], check=True)
            sequence = snapshot['parsed']['metadata']['keylist_seq'] + 1 if snapshot else 1
            payload = keys.build_keylist_payload(_file(krl, keys.MAX_KRL_BYTES), keylist_seq=sequence,
                issued_at=now, signer_root_id=root_id)
        record.update(state='retirement-pending', retirement_payload=base64.b64encode(payload).decode(), retirement_base=baseline)
        _save(paths, record)
        return {'request_id': record['id'], 'payload': record['retirement_payload'], 'root_id': root_id}


def retire(request_id, artifact, *, paths=None, now=None):
    paths = paths or keys.InstructionPaths.from_env()
    now = int(time.time()) if now is None else now
    artifact = _decode(artifact, keys.MAX_KEYLIST_BYTES)
    parsed = keys.parse_keylist_artifact(artifact)
    with keys._custody_lock(paths):
        record = _load(paths)
        _require(record, request_id)
        if record['state'] not in ('retirement-pending', 'retiring', 'completed'):
            raise keys.InstructionKeyError('rotation is not awaiting retirement')
        if parsed['payload'] != _decode(record['retirement_payload'], keys.MAX_KEYLIST_PAYLOAD_BYTES):
            raise keys.InstructionKeyError('approval does not match the retirement request')
        roots = _roots(paths)
        if _file(paths.public_key).decode('ascii') != record['new_public']:
            raise keys.InstructionKeyError('active signer changed; review custody before retirement')
        if record['state'] == 'completed':
            snapshot = keys._load_keylist_snapshot_locked(paths)
            if not snapshot or not snapshot['metadata_consistent'] or snapshot['bytes'] != artifact:
                raise keys.InstructionKeyError('keylist changed after retirement; refresh custody evidence')
            return _view(record, roots)
        private, public = keys._ensure_runtime_key_locked(paths, required=True)
        keys._certificate_operation_locked(paths, private, public, _file(paths.certificate), roots,
            now=now, krl=parsed['krl'], body=b'IRIS replacement signer retirement check\n',
            timeout=keys.SSH_TIMEOUT, ssh_keygen='ssh-keygen')
        # Prove the intended key is revoked, without ever signing with it again.
        with tempfile.TemporaryDirectory(dir=keys._runtime_directory(paths)) as directory:
            krl, old, new = (Path(directory) / name for name in ('revocations.krl', 'old.pub', 'new.pub'))
            for target, content in ((krl, parsed['krl']), (old, record['old_public'].encode()),
                                    (new, record['new_public'].encode())):
                keys._atomic_write(target, content)
            if (keys._run_ssh(['-Q', '-f', str(krl), str(old)]).returncode != 1
                    or keys._run_ssh(['-Q', '-f', str(krl), str(new)]).returncode != 0):
                raise keys.InstructionKeyError('retirement must revoke only the intended signer')
        snapshot = keys._load_keylist_snapshot_locked(paths)
        current = snapshot['parsed']['artifact_sha256'] if snapshot else None
        if current not in (record['retirement_base'], parsed['artifact_sha256']):
            raise keys.InstructionKeyError('keylist changed; prepare retirement again')
        # Existing verifier authenticates roots, sequence, and metadata repair.
        keys._verify_keylist(parsed, roots, previous_krl=snapshot['parsed']['krl'] if snapshot else None,
                            timeout=keys.SSH_TIMEOUT, ssh_keygen='ssh-keygen')
        record['state'] = 'retiring'
        _save(paths, record)
    keys.install_keylist(paths, artifact, roots, now=now)
    with keys._custody_lock(paths):
        record = _load(paths)
        _require(record, request_id)
        snapshot = keys._load_keylist_snapshot_locked(paths)
        if not snapshot or not snapshot['metadata_consistent'] or snapshot['bytes'] != artifact:
            raise keys.InstructionKeyError('keylist changed during retirement; verify and retry')
        record.update(state='completed', retired_seq=parsed['metadata']['keylist_seq'])
        _save(paths, record)
        return _view(record, _roots(paths))


def operate(payload, *, paths=None, now=None):
    """Closed web/CLI contract: public approvals only, no paths or commands."""
    fields = {'prepare': {'action', 'request_id'}, 'cancel': {'action', 'request_id'},
              'activate': {'action', 'request_id', 'certificate', 'confirm'},
              'retirement-request': {'action', 'request_id', 'root_id'},
              'retire': {'action', 'request_id', 'artifact', 'confirm'}}
    if (not isinstance(payload, dict) or not isinstance(payload.get('action'), str)
            or payload['action'] not in fields or set(payload) != fields[payload['action']]):
        raise keys.InstructionKeyError('invalid rotation fields')
    action, request_id = payload['action'], payload['request_id']
    if action in ('activate', 'retire') and payload['confirm'] is not True:
        raise keys.InstructionKeyError('confirm the rotation impact before applying')
    if action == 'prepare':
        return prepare(request_id, paths=paths, now=now)
    if action == 'cancel':
        return cancel(request_id, paths=paths)
    if action == 'activate':
        return activate(request_id, payload['certificate'], paths=paths, now=now)
    if action == 'retirement-request':
        if not isinstance(payload['root_id'], str):
            raise keys.InstructionKeyError('choose a configured root')
        return retirement_request(request_id, payload['root_id'], paths=paths, now=now)
    return retire(request_id, payload['artifact'], paths=paths, now=now)
