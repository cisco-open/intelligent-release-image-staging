# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Public approval and stopped-writer publication of deployment trust.

The Console may prepare and approve, but cannot publish these changes. The
installer's maintenance worker proves recoverable backup and stopped services,
then invokes ``apply_prepared`` in a one-shot container. No offline private root
is accepted. A root transition re-signs the exact existing KRL, preserving every
revocation and the instruction epoch, rather than resetting signing custody.
"""

import base64
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import time

import instruction_keys as keys
import secretfs
import tls_rotation as tls

FAMILIES = ('device-tls', 'peer-ca', 'instruction-roots')
STATES = ('awaiting-approval', 'approved', 'committing', 'published', 'cancelled')
PUBLIC = ('family', 'request_id', 'state', 'created_at', 'names', 'mode', 'csr',
          'certificate', 'fingerprint_sha256', 'roots', 'online_public_key',
          'keylist_payload', 'keylist_signer', 'requires_reonboarding',
          'requires_package_rebuild', 'attested_root_ids', 'attestation_request_id', 'attestation_root_id')
DERIVED = {'attested_root_ids', 'attestation_request_id', 'attestation_root_id'}


class RotationError(ValueError):
    pass


def _family(value):
    if not isinstance(value, str) or value not in FAMILIES:
        raise RotationError('Unknown trust family')
    return value


def journal_path(family):
    return Path(keys.InstructionPaths.from_env().config_dir) / 'trust-rotation' / (_family(family) + '.json')


@contextmanager
def _lock():
    directory = journal_path('device-tls').parent
    if directory.is_symlink():
        raise RotationError('Unsafe trust rotation directory')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(directory / 'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _read(path):
    if not keys._path_exists(path, 'Trust rotation authority is unavailable'):
        return None
    return keys._read_regular(path, 16 * 1024 * 1024,
        unavailable='Trust rotation authority is unavailable', too_large='Trust rotation authority is oversized')


def _sha(value):
    return None if value is None else hashlib.sha256(value).hexdigest()


def _encode(value):
    return base64.b64encode(value).decode('ascii')


def _decode(value):
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise RotationError('Trust rotation material is invalid') from None


def _targets(record):
    paths = keys.InstructionPaths.from_env()
    config = Path(paths.config_dir)
    if record['family'] == 'device-tls':
        return {'key': config / 'tls/key.pem.age', 'certificate': config / 'tls/crt.pem'}
    if record['family'] == 'peer-ca':
        return {'key': config / 'peer-tls/ca.pem.age'}
    return {**{'root:' + name: Path(paths.roots_dir) / (name + '.pub') for name in record['roots']},
            'certificate': Path(paths.certificate), 'keylist': Path(paths.keylist_current),
            'keylist-state': Path(paths.keylist_state)}


def _load(family):
    raw = _read(journal_path(family))
    if raw is None:
        return None
    value = keys._strict_json_loads(raw, 'trust rotation journal')
    if (not isinstance(value, dict) or set(value) != (set(PUBLIC) - DERIVED) | {'schema', 'candidate', 'before', 'outputs', 'guards', 'attestation'}
            or value.get('schema') != 1 or value.get('family') != family
            or value.get('state') not in STATES):
        raise RotationError('Invalid trust rotation journal; preserve it for recovery')
    tls._id(value['request_id'])
    if not isinstance(value['roots'], dict) or not isinstance(value['before'], dict) or not isinstance(value['outputs'], dict):
        raise RotationError('Invalid trust rotation targets')
    if family == 'instruction-roots':
        _roots(value['roots'])
    if set(value['before']) != set(_targets(value)) or not set(value['outputs']) <= set(value['before']):
        raise RotationError('Invalid trust rotation target set')
    if type(value['created_at']) is not int or value['created_at'] < 0:
        raise RotationError('Invalid trust rotation creation time')
    for digest in [*value['before'].values(), value['fingerprint_sha256']]:
        if digest is not None and (not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)):
            raise RotationError('Invalid trust rotation digest')
    if value['state'] in ('approved', 'committing') and set(value['outputs']) != set(value['before']):
        raise RotationError('Approved trust rotation is incomplete')
    if value['state'] in ('published', 'cancelled') and (value['candidate'] is not None or value['outputs']):
        raise RotationError('Finished trust rotation retained candidate material')
    if family == 'device-tls':
        if tls._names(value['names']) != value['names'] or value['mode'] not in ('ca', 'self-signed'):
            raise RotationError('Invalid device TLS request')
        if value['state'] not in ('published', 'cancelled'):
            tls._ciphertext(dict(ciphertext=value['candidate']))
    if family in ('device-tls', 'peer-ca') and 'key' in value['outputs']:
        tls._ciphertext(dict(ciphertext=value['outputs']['key']))
    pending = value['attestation']
    if pending is not None:
        if (family != 'instruction-roots' or not isinstance(pending, dict)
                or set(pending) != {'root_id', 'payload', 'baseline', 'artifact_sha256'}
                or not isinstance(pending['root_id'], str) or pending['root_id'] not in value['roots']
                or not isinstance(pending['payload'], str)):
            raise RotationError('Invalid root attestation request')
        keys._parse_keylist_payload(pending['payload'].encode('ascii'))
        for digest in (pending['baseline'], pending['artifact_sha256']):
            if digest is not None and (not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)):
                raise RotationError('Invalid root attestation baseline')
    return value


def _save(record):
    keys._atomic_write_json(journal_path(record['family']), record)


def _view(record, family, *, live=True):
    if record is None:
        view = dict(family=family, request_id=None, state='idle', created_at=None, names=[], mode=None,
                    csr=None, certificate=None, fingerprint_sha256=None, roots={}, online_public_key=None,
                    keylist_payload=None, keylist_signer=None, requires_reonboarding=True,
                    requires_package_rebuild=family == 'instruction-roots')
    else:
        view = {name: record[name] for name in PUBLIC if name not in DERIVED}
    view.update(attested_root_ids=[], attestation_request_id=None, attestation_root_id=None)
    if live and family == 'instruction-roots' and view['state'] in ('idle', 'cancelled', 'published'):
        current = keys.discover_roots(keys.InstructionPaths.from_env())
        view['roots'] = {name: public.decode('ascii') for name, public in current.items()}
        ceremony = _load_attestation()
        if ceremony and _roots(ceremony['roots']) == current:
            view.update(attestation_request_id=ceremony['request_id'],
                        attestation_root_id=ceremony['attestation']['root_id'] if ceremony['attestation'] else None)
        info = keys.keylist_info(keys.InstructionPaths.from_env())
        if info and info['metadata_consistent']:
            now = int(time.time())
            view['attested_root_ids'] = sorted(name for name, attestation in info['root_attestations'].items()
                if name in current and attestation['key_sha256'] == keys._root_digest(current[name])
                and now - 180 * 86400 <= attestation['attested_at'] <= now + keys.CERTIFICATE_TIME_TOLERANCE)
    return view


def status(family):
    _family(family)
    with _lock():
        return _view(_load(family), family)


def _roots(value):
    if not isinstance(value, dict) or len(value) != 2:
        raise RotationError('Provide exactly two offline public roots')
    result = {}
    for name, public in value.items():
        if not isinstance(name, str) or not keys._ROOT_ID.fullmatch(name) or not isinstance(public, str) or 'PRIVATE' in public:
            raise RotationError('Import only named offline public roots')
        result[name] = keys._public_key_bytes(public.encode('ascii'))
    if len(set(result.values())) != 2:
        raise RotationError('Offline roots must be distinct')
    return result


def _guard_values():
    paths = keys.InstructionPaths.from_env()
    return {'epoch': _sha(_read(paths.epoch)), 'signing-key': _sha(_read(paths.encrypted_key)),
            'signing-public': _sha(_read(paths.public_key))}


def _signer_idle(paths):
    import instruction_rotation
    pending = instruction_rotation._load(paths)
    if pending and pending['state'] not in ('completed', 'cancelled'):
        raise RotationError('Finish online signer replacement and retirement before changing offline roots')


def _prepare_tls(record):
    with tls._runtime() as directory:
        private, cipher = directory / 'key.pem', directory / 'key.age'
        tls._openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', private)
        private.chmod(0o600)
        if record['family'] == 'peer-ca':
            cert = tls._openssl('req', '-x509', '-new', '-key', private, '-days', '3650',
                '-subj', '/CN=IRIS Private Swarm CA', '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
                '-addext', 'keyUsage=critical,keyCertSign,cRLSign').decode('ascii')
            combined = directory / 'combined.pem'
            keys._atomic_write(combined, cert.encode('ascii') + private.read_bytes())
            secretfs.encrypt_from(str(combined), str(cipher), os.environ['IRIS_AGE_RECIPIENTS'])
            recovered = directory / 'recovered.pem'
            secretfs.decrypt_to(str(cipher), str(recovered), os.environ['IRIS_AGE_KEY_FILE'])
            if recovered.read_bytes() != combined.read_bytes():
                raise RotationError('Replacement issuer cannot be recovered')
            record.update(certificate=cert, fingerprint_sha256=_sha(ssl.PEM_cert_to_DER_cert(cert)),
                          state='approved', outputs={'key': _encode(cipher.read_bytes())})
        else:
            import ipaddress
            sans = []
            for name in record['names']:
                try:
                    ipaddress.ip_address(name)
                    sans.append('IP:' + name)
                except ValueError:
                    sans.append('DNS:' + name)
            extensions = ['-subj', '/CN=IRIS Distribution', '-addext', 'subjectAltName=' + ','.join(sans),
                          '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'extendedKeyUsage=serverAuth']
            record['csr'] = tls._openssl('req', '-new', '-key', private, *extensions).decode('ascii')
            secretfs.encrypt_from(str(private), str(cipher), os.environ['IRIS_AGE_RECIPIENTS'])
            record['candidate'] = _encode(cipher.read_bytes())
            with tls._material(dict(record, ciphertext=record['candidate'])):
                pass
            if record['mode'] == 'self-signed':
                cert = tls._openssl('req', '-x509', '-new', '-key', private, '-days', '90', *extensions).decode('ascii')
                _approve_tls(record, cert)


def _approve_tls(record, certificate, *, admission=True):
    material = dict(record, ciphertext=record['candidate'])
    with tls._material(material) as private:
        cert, digest = tls._validate_certificate(material, certificate, private, admission=admission)
    record.update(certificate=cert, fingerprint_sha256=digest, state='approved',
                  outputs={'key': record['candidate'], 'certificate': _encode(cert.encode('ascii'))})


def _validate_peer(record, *, admission):
    with tls._runtime() as directory:
        cipher, material = directory / 'peer.age', directory / 'peer.pem'
        keys._atomic_write(cipher, _decode(record['outputs']['key']))
        secretfs.decrypt_to(str(cipher), str(material), os.environ['IRIS_AGE_KEY_FILE'])
        der = tls._openssl('x509', '-in', material, '-outform', 'DER')
        if (_sha(der) != record['fingerprint_sha256'] or
                tls._openssl('pkey', '-in', material, '-pubout') != tls._openssl('x509', '-in', material, '-pubkey', '-noout')):
            raise RotationError('Replacement peer issuer does not match its approval')
        if admission:
            tls._openssl('x509', '-in', material, '-checkend', str(7 * 86400), '-noout')


def _prepare_roots(record):
    paths = keys.InstructionPaths.from_env()
    current = keys.discover_roots(paths)
    replacement = _roots(record['roots'])
    if set(current) != set(replacement):
        raise RotationError('Keep the existing two root IDs when replacing their public keys')
    if replacement == current:
        raise RotationError('Replacement roots must change at least one public key')
    signer = record['keylist_signer']
    if signer not in replacement:
        raise RotationError('Select one replacement root to approve the preserved keylist')
    with keys._custody_lock(paths):
        _signer_idle(paths)
        snapshot = keys._load_keylist_snapshot_locked(paths)
        if snapshot is not None and not snapshot['metadata_consistent']:
            raise RotationError('Repair the current keylist before replacing roots')
        if snapshot is not None:
            keys._verify_keylist(snapshot['parsed'], current, previous_krl=None,
                                 timeout=keys.SSH_TIMEOUT, ssh_keygen='ssh-keygen')
        krl = b'' if snapshot is None else snapshot['parsed']['krl']
        seq = 1 if snapshot is None else snapshot['parsed']['metadata']['keylist_seq'] + 1
        issued = record['created_at']
        if snapshot and issued < snapshot['parsed']['metadata']['issued_at']:
            raise RotationError('Clock is behind the installed keylist')
        payload = keys.build_keylist_payload(krl, keylist_seq=seq, issued_at=issued, signer_root_id=signer)
        record['keylist_payload'] = payload.decode('ascii')
        record['online_public_key'] = keys._public_key_bytes(paths.public_key).decode('ascii')
        record['guards'] = _guard_values()


def _approve_roots(record, certificate, artifact):
    if not isinstance(certificate, str) or len(certificate) > keys.MAX_CERTIFICATE_BYTES or 'PRIVATE' in certificate:
        raise RotationError('Import only the approved online public certificate')
    if not isinstance(artifact, str) or len(artifact) > keys.MAX_KEYLIST_BYTES:
        raise RotationError('Import a bounded public signed keylist')
    paths = keys.InstructionPaths.from_env()
    roots = _roots(record['roots'])
    parsed = keys.parse_keylist_artifact(artifact.encode('ascii'))
    if parsed['payload'] != record['keylist_payload'].encode('ascii'):
        raise RotationError('Keylist must approve this exact preserved-revocation request')
    signer = keys._verify_keylist(parsed, roots, previous_krl=parsed['krl'] or None,
                                  timeout=keys.SSH_TIMEOUT, ssh_keygen='ssh-keygen')
    with tls._runtime() as directory:
        candidate = directory / 'online-cert.pub'
        keys._atomic_write(candidate, certificate.encode('ascii'))
        keys.validate_online_certificate(paths, candidate, roots)
    # Existing attestations belong to the old root identities. Record only the
    # verified new ceremony, never carry over freshness from the replaced roots.
    state = keys._keylist_state(parsed, signer, roots, None, now=int(time.time()))
    record.update(certificate=certificate, state='approved',
        fingerprint_sha256=_sha(certificate.encode('ascii')), outputs={
            **{'root:' + name: _encode(public) for name, public in roots.items()},
            'certificate': _encode(certificate.encode('ascii')), 'keylist': _encode(artifact.encode('ascii')),
            'keylist-state': _encode((json.dumps(state, sort_keys=True) + '\n').encode())})


def _attestation_path():
    return journal_path('instruction-roots').with_name('root-attestation.json')


def _load_attestation():
    raw = _read(_attestation_path())
    if raw is None:
        return None
    record = keys._strict_json_loads(raw, 'root attestation journal')
    if (not isinstance(record, dict) or set(record) != {'schema', 'request_id', 'state', 'roots', 'attestation'}
            or record['schema'] != 1 or record['state'] != 'attestation-only'):
        raise RotationError('Invalid independent root attestation authority')
    tls._id(record['request_id'])
    roots = _roots(record['roots'])
    pending = record['attestation']
    if (not isinstance(pending, dict) or set(pending) != {'root_id', 'payload', 'baseline', 'artifact_sha256'}
            or not isinstance(pending['root_id'], str) or pending['root_id'] not in roots
            or not isinstance(pending['payload'], str)):
        raise RotationError('Invalid independent root attestation request')
    keys._parse_keylist_payload(pending['payload'].encode('ascii'))
    for digest in (pending['baseline'], pending['artifact_sha256']):
        if digest is not None and (not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)):
            raise RotationError('Invalid independent attestation baseline')
    return record


def _attest(record, payload):
    """Re-sign the installed KRL with an independently held current root."""
    paths = keys.InstructionPaths.from_env()
    root_id = payload['root_id']
    if not isinstance(root_id, str) or root_id not in record['roots']:
        raise RotationError('Choose a configured current root for attestation')
    def save():
        keys._atomic_write_json(_attestation_path(), record)
    with keys._custody_lock(paths):
        roots = keys.discover_roots(paths)
        if roots != _roots(record['roots']):
            raise RotationError('Configured roots changed after this replacement')
        snapshot = keys._load_keylist_snapshot_locked(paths)
        baseline = snapshot['parsed']['artifact_sha256'] if snapshot else None
        pending = record['attestation']
        if payload['action'] == 'attestation-request':
            if snapshot and not snapshot['metadata_consistent']:
                raise RotationError('Finish the interrupted keylist publication before another request')
            if pending and pending['root_id'] == root_id and pending['baseline'] == baseline:
                return {'request_id': record['request_id'], 'root_id': root_id, 'payload': pending['payload']}
            if snapshot:
                keys._verify_keylist(snapshot['parsed'], roots, previous_krl=None,
                                     timeout=keys.SSH_TIMEOUT, ssh_keygen='ssh-keygen')
            issued = int(time.time())
            if snapshot and issued < snapshot['parsed']['metadata']['issued_at']:
                raise RotationError('Clock is behind the installed keylist')
            request = keys.build_keylist_payload(snapshot['parsed']['krl'] if snapshot else b'',
                keylist_seq=snapshot['parsed']['metadata']['keylist_seq'] + 1 if snapshot else 1,
                issued_at=issued, signer_root_id=root_id).decode('ascii')
            record['attestation'] = dict(root_id=root_id, payload=request, baseline=baseline, artifact_sha256=None)
            save()
            return {'request_id': record['request_id'], 'root_id': root_id, 'payload': request}
        artifact = payload['keylist']
        if not isinstance(artifact, str) or len(artifact) > keys.MAX_KEYLIST_BYTES:
            raise RotationError('Import a bounded public signed keylist')
        parsed = keys.parse_keylist_artifact(artifact.encode('ascii'))
        if not pending or root_id != pending['root_id'] or parsed['payload'] != pending['payload'].encode('ascii'):
            raise RotationError('Approval does not match this independent root attestation request')
        if baseline not in (pending['baseline'], parsed['artifact_sha256']):
            raise RotationError('Keylist changed; prepare the independent attestation again')
        if pending['artifact_sha256'] not in (None, parsed['artifact_sha256']):
            raise RotationError('An admitted root attestation cannot change its approval')
        keys._verify_keylist(parsed, roots, previous_krl=(snapshot['parsed']['krl'] or None) if snapshot else None,
                             timeout=keys.SSH_TIMEOUT, ssh_keygen='ssh-keygen')
        pending['artifact_sha256'] = parsed['artifact_sha256']
        save()
    # Standard installer owns its custody lock and crash-repair rules. A newer
    # concurrent artifact cannot be overwritten: our exact sequence is pinned.
    keys.install_keylist(paths, artifact.encode('ascii'), roots)
    with keys._custody_lock(paths):
        snapshot = keys._load_keylist_snapshot_locked(paths)
        if not snapshot or not snapshot['metadata_consistent'] or snapshot['bytes'] != artifact.encode('ascii'):
            raise RotationError('Keylist changed during publication; inspect custody and retry')
        replacement = _load('instruction-roots')
        if replacement and replacement['state'] == 'published' and _roots(replacement['roots']) == roots:
            replacement['before']['keylist'] = _sha(_read(paths.keylist_current))
            replacement['before']['keylist-state'] = _sha(_read(paths.keylist_state))
            _save(replacement)
        save()
    return _view(replacement, 'instruction-roots')


def operate(payload):
    if not isinstance(payload, dict):
        raise RotationError('Expected one trust rotation action')
    family = _family(payload.get('family'))
    action = payload.get('action')
    fields = {'prepare': ({'names', 'mode'} if family == 'device-tls' else
                          {'roots', 'keylist_signer'} if family == 'instruction-roots' else set()),
              'approve': {'certificate', 'keylist'} if family == 'instruction-roots' else {'certificate'},
              'cancel': set()}
    if family == 'instruction-roots':
        fields.update({'attestation-request': {'root_id'}, 'attestation-apply': {'root_id', 'keylist'}})
    if not isinstance(action, str) or action not in fields or set(payload) != {'family', 'action', 'request_id'} | fields[action]:
        raise RotationError('Unexpected trust rotation fields')
    tls._id(payload['request_id'])
    with _lock():
        record = _load(family)
        if action in ('attestation-request', 'attestation-apply'):
            if record and record['state'] not in ('published', 'cancelled'):
                raise RotationError('Finish or cancel the root replacement before attesting current roots')
            ceremony = _load_attestation()
            if action == 'attestation-request' and (ceremony is None or ceremony['request_id'] != payload['request_id']):
                roots = keys.discover_roots(keys.InstructionPaths.from_env())
                if len(roots) != 2:
                    raise RotationError('Configure exactly two public roots before attestation')
                ceremony = dict(schema=1, state='attestation-only', request_id=payload['request_id'],
                    roots={name: value.decode('ascii') for name, value in roots.items()}, attestation=None)
            if ceremony is None or ceremony['request_id'] != payload['request_id']:
                raise RotationError('Independent attestation request changed; refresh before continuing')
            return _attest(ceremony, payload)
        if action == 'prepare':
            names = tls._names(payload['names']) if family == 'device-tls' else []
            mode = payload.get('mode')
            if family == 'device-tls' and mode not in ('ca', 'self-signed'):
                raise RotationError('Choose CA approval or explicit self-signed replacement')
            roots = {name: value.decode('ascii') for name, value in _roots(payload['roots']).items()} if family == 'instruction-roots' else {}
            if record and record['request_id'] == payload['request_id']:
                if (record['names'], record['mode'], record['roots'], record['keylist_signer']) != (names, mode, roots, payload.get('keylist_signer')):
                    raise RotationError('Request ID belongs to different trust parameters')
                return _view(record, family)
            if any((pending := _load(other)) and pending['state'] not in ('published', 'cancelled') for other in FAMILIES):
                raise RotationError('Finish or cancel the pending trust rotation')
            record = dict(schema=1, family=family, request_id=payload['request_id'], state='awaiting-approval',
                created_at=int(time.time()), names=names, mode=mode, roots=roots, csr=None, certificate=None,
                fingerprint_sha256=None, online_public_key=None, keylist_payload=None,
                keylist_signer=payload.get('keylist_signer'), requires_reonboarding=True,
                requires_package_rebuild=family == 'instruction-roots', candidate=None, outputs={}, before={}, guards={}, attestation=None)
            record['before'] = {name: _sha(_read(path)) for name, path in _targets(record).items()}
            if family == 'instruction-roots':
                _prepare_roots(record)
            else:
                if not os.environ.get('IRIS_AGE_RECIPIENTS') or not os.environ.get('IRIS_AGE_KEY_FILE'):
                    raise RotationError('Encrypted recoverable key storage must be configured')
                _prepare_tls(record)
            _save(record)
        else:
            if not record or record['request_id'] != payload['request_id']:
                raise RotationError('Trust request changed; refresh before continuing')
            if record['state'] not in ('awaiting-approval', 'approved', 'cancelled'):
                raise RotationError('An admitted trust change cannot be approved or cancelled')
            if action == 'cancel':
                record.update(state='cancelled', candidate=None, outputs={})
            elif record['state'] == 'cancelled':
                raise RotationError('Cancelled requests cannot be approved')
            elif family == 'instruction-roots':
                _approve_roots(record, payload['certificate'], payload['keylist'])
            elif family == 'device-tls':
                _approve_tls(record, payload['certificate'])
            else:
                raise RotationError('Peer CA replacement is generated and approved during preparation')
            _save(record)
        return _view(record, family)


def drain_status():
    """Read durable deployment authority, including principals missing from fleet.

    Must be re-evaluated after all service writers have stopped. An abandoned
    record is not removal proof. A superseded record is safe only when a later
    deployment for that same device has been positively removed.
    """
    import deployment_records
    import secrets_store
    paths = keys.InstructionPaths.from_env()
    records = deployment_records.DeploymentRecordStore(paths.state_dir).list(strict=True)
    removed = {r['device_id']: max(r.get('timestamps', {}).get('finished_at', 0), 0)
               for r in sorted(records, key=lambda r: r.get('timestamps', {}).get('finished_at', 0)) if r['state'] == 'removed'}
    blocked = set()
    for record in records:
        if record['state'] == 'removed':
            continue
        if record['state'] == 'superseded' and removed.get(record['device_id'], -1) >= record.get('timestamps', {}).get('finished_at', 0):
            continue
        blocked.add(record['device_id'])
    with tls._runtime() as directory:
        plaintext = directory / 'secrets.json'
        secretfs.decrypt_to(str(Path(paths.config_dir) / 'secrets.json.age'), str(plaintext), os.environ['IRIS_AGE_KEY_FILE'])
        store = secrets_store.load(str(plaintext), require_existing=True)
        if not isinstance(store.get('devices'), dict):
            raise RotationError('Device credential authority is invalid')
        for device_id, credentials in store['devices'].items():
            if not isinstance(credentials, dict) or device_id not in removed:
                blocked.add(device_id)
                continue
            for credential in credentials.values():
                if not isinstance(credential, dict):
                    blocked.add(device_id)
                elif credential.get('revoked') is not True and (
                        type(credential.get('created_at')) is not int or
                        credential['created_at'] > removed[device_id]):
                    # A later mint may belong to an out-of-band installation;
                    # an older removed record is not proof that it was drained.
                    blocked.add(device_id)
    return {'ready': not blocked, 'blocked_device_ids': sorted(blocked), 'removed_device_ids': sorted(removed)}


def check_prepared(family, request_id):
    """Stopped-writer admission check with no durable publication or approval."""
    _family(family)
    tls._id(request_id)
    with _lock():
        record = _load(family)
        if not record or record['request_id'] != request_id or record['state'] != 'approved':
            raise RotationError('Prepare and approve this exact trust replacement first')
        if not drain_status()['ready']:
            raise RotationError('Remove all deployed IRIS agents before changing deployment trust')
        if any(_sha(_read(path)) != record['before'][name] for name, path in _targets(record).items()):
            raise RotationError('Trust files changed after approval; prepare a new request')
        if family == 'instruction-roots':
            _signer_idle(keys.InstructionPaths.from_env())
            if record['guards'] != _guard_values():
                raise RotationError('Instruction epoch or online signing identity changed; prepare a new request')
            _approve_roots(record, record['certificate'], _decode(record['outputs']['keylist']).decode('ascii'))
        elif family == 'device-tls':
            _approve_tls(record, record['certificate'])
        else:
            _validate_peer(record, admission=True)
        return {'ready': True, 'family': family, 'request_id': request_id}


def apply_prepared(family, request_id):
    """Maintenance-only entry point; caller must prove stopped service writers."""
    _family(family)
    tls._id(request_id)
    with _lock():
        record = _load(family)
        if not record or record['request_id'] != request_id or record['state'] not in ('approved', 'committing', 'published'):
            raise RotationError('No approved trust replacement matches this request')
        if record['state'] == 'published':
            if any(_sha(_read(path)) != record['before'][name] for name, path in _targets(record).items()):
                raise RotationError('Published trust changed outside this request')
            return _view(record, family)
        if not drain_status()['ready']:
            raise RotationError('Remove all deployed IRIS agents before changing deployment trust')
        if family == 'instruction-roots' and record['guards'] != _guard_values():
            raise RotationError('Instruction epoch or online signing identity changed; prepare a new request')
        if family == 'instruction-roots':
            _signer_idle(keys.InstructionPaths.from_env())
        recovering = record['state'] == 'committing'
        if not recovering:
            if family == 'device-tls':
                _approve_tls(record, record['certificate'])
            elif family == 'instruction-roots':
                _approve_roots(record, record['certificate'], _decode(record['outputs']['keylist']).decode('ascii'))
        if family == 'peer-ca':
            _validate_peer(record, admission=not recovering)
        outputs = {name: _decode(value) for name, value in record['outputs'].items()}
        targets = _targets(record)
        if set(outputs) != set(targets):
            raise RotationError('Approved trust publication is incomplete')
        current = {name: _sha(_read(path)) for name, path in targets.items()}
        for name, digest in current.items():
            allowed = (record['before'][name], _sha(outputs[name])) if recovering else (record['before'][name],)
            if digest not in allowed:
                raise RotationError('Trust files changed outside this request; preserve them for recovery')
        record['state'] = 'committing'
        _save(record)
        for name, path in targets.items():
            keys._atomic_write(path, outputs[name], mode=0o600 if name in ('key', 'keylist-state') else 0o644)
        record.update(state='published', candidate=None, outputs={}, before={name: _sha(data) for name, data in outputs.items()})
        _save(record)
        return _view(record, family)
