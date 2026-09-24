# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Owner-managed metrics and collector credentials in existing age custody.

Overrides never rewrite deployment-mounted files. Secrets stay in the encrypted
secrets store and its private runtime copy; status and proof contain public IDs.
Retirement requires observed use of this replacement plus operator confirmation.
"""

import hmac
import os
from pathlib import Path
import re
import time
import uuid
from urllib.parse import urlsplit

import instruction_keys as keys
import secretfs
import secrets_store
import tier_auth

FAMILIES = ('metrics-token', 'collector-headers')


class CredentialError(ValueError):
    pass


def _path():
    return os.environ.get('IRIS_SECRETS', '')


def _load():
    path = _path()
    if not path:
        return {'devices': {}, 'seeder': {}}
    try:
        return secrets_store.load(path, require_existing=bool(os.environ.get('IRIS_SECRETS_ENC')))
    except (OSError, ValueError):
        raise CredentialError('Encrypted service credential storage is unavailable') from None


def _token(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9._~+/-]{32,256}', value):
        raise CredentialError('Use a 32–256 character credential without spaces')
    return value


def _headers(value):
    if not isinstance(value, dict) or not 1 <= len(value) <= 16:
        raise CredentialError('Provide 1–16 collector authentication headers')
    result = {}
    for name, content in value.items():
        if (not isinstance(name, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}", name)
                or name.lower() in {'host', 'content-length', 'content-type', 'transfer-encoding', 'connection', 'accept-encoding'}
                or name.lower() in result or not isinstance(content, str)
                or not 1 <= len(content) <= 4096 or any(ord(c) < 32 or ord(c) > 126 for c in content)):
            raise CredentialError('Invalid collector authentication header')
        result[name.lower()] = content
    if sum(len(k) + len(v) for k, v in result.items()) > 16384:
        raise CredentialError('Collector headers exceed 16 KiB')
    return result


def _endpoint(value):
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise CredentialError('Provide an HTTPS collector base URL')
    try:
        parsed = urlsplit(value)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError()
        parsed.port
    except ValueError:
        raise CredentialError('Provide an HTTPS collector base URL without credentials or query parameters') from None
    return value.rstrip('/')


def _id(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError()
    except ValueError:
        raise CredentialError('Use a canonical credential operation ID') from None


def _record(store, family):
    records = store.get('service_credentials', {})
    if not isinstance(records, dict) or any(name not in FAMILIES for name in records):
        raise CredentialError('Invalid service credential storage')
    record = records.get(family)
    if record is None:
        return None
    if (not isinstance(record, dict) or set(record) != {'request_id', 'state', 'started_at', 'current', 'previous', 'endpoint', 'previous_managed', 'previous_endpoint'}
            or record['state'] not in ('awaiting-verification', 'completed', 'reverted')
            or type(record['previous_managed']) is not bool
            or type(record['started_at']) is not int or record['started_at'] < 0):
        raise CredentialError('Invalid service credential operation')
    _id(record['request_id'])
    if record['state'] == 'reverted' and record['current'] is None and record['previous'] is None and record['endpoint'] is None:
        return record
    if family == 'collector-headers':
        _headers(record['current'])
        _endpoint(record['endpoint'])
        if record['previous_endpoint'] is not None:
            _endpoint(record['previous_endpoint'])
        if record['previous'] is not None:
            _headers(record['previous'])
    else:
        _token(record['current'])
        if record['previous'] is not None and not isinstance(record['previous'], str):
            raise CredentialError('Invalid previous scrape credential')
        if record['endpoint'] is not None:
            raise CredentialError('Metrics credentials do not select an endpoint')
    return record


def _proof_path(family):
    return Path(os.environ.get('IRIS_STATE', '/srv/state')) / 'credential-proof' / (family + '.json')


def _proof(record, family):
    path = _proof_path(family)
    if record is None or record['state'] == 'reverted' or not path.exists():
        return None
    try:
        proof = keys._strict_json_loads(keys._read_regular(path, 2048,
            unavailable='credential proof unavailable', too_large='credential proof oversized'), 'credential proof')
        if (set(proof) == {'request_id', 'observed_at'} and proof['request_id'] == record['request_id']
                and type(proof['observed_at']) is int and record['started_at'] <= proof['observed_at'] <= int(time.time()) + 30):
            return proof['observed_at']
    except (OSError, ValueError, TypeError, keys.InstructionKeyError):
        pass
    return None


def _observed(record, family):
    if record['state'] == 'awaiting-verification' and _proof(record, family) is None:
        keys._atomic_write_json(_proof_path(family), dict(request_id=record['request_id'], observed_at=int(time.time())))


def status():
    store = _load()
    result = []
    for family in FAMILIES:
        record = _record(store, family)
        result.append(dict(family=family, request_id=record['request_id'] if record else None,
            state=record['state'] if record else 'deployment-managed',
            previous_retained=bool(record and record['previous'] is not None),
            started_at=record['started_at'] if record else None, observed_at=_proof(record, family),
            endpoint=record['endpoint'] if record else None))
    return {'items': result}


def operate(payload):
    if not isinstance(payload, dict):
        raise CredentialError('Expected a credential operation')
    family, action = payload.get('family'), payload.get('action')
    if family not in FAMILIES or action not in ('replace', 'retire', 'revert'):
        raise CredentialError('Unknown credential operation')
    fields = {'family', 'action', 'request_id', 'confirm'}
    if action == 'replace':
        fields |= {'token'} if family == 'metrics-token' else {'headers', 'endpoint'}
    if set(payload) != fields or payload['confirm'] is not True:
        raise CredentialError('Confirm the bounded credential change')
    _id(payload['request_id'])
    path, encrypted, recipients = _path(), os.environ.get('IRIS_SECRETS_ENC'), os.environ.get('IRIS_AGE_RECIPIENTS')
    if not path or not encrypted or not recipients or not Path(encrypted).is_file():
        raise CredentialError('Durable encrypted credential storage must be configured')
    with secrets_store.store_lock(path):
        store = _load()
        record = _record(store, family)
        if action == 'replace':
            current = _token(payload['token']) if family == 'metrics-token' else _headers(payload['headers'])
            endpoint = None if family == 'metrics-token' else _endpoint(payload['endpoint'])
            if record and record['request_id'] == payload['request_id']:
                if record['current'] != current or record['endpoint'] != endpoint:
                    raise CredentialError('Request ID belongs to different credentials')
                return status()
            if record and record['state'] not in ('completed', 'reverted'):
                raise CredentialError('Verify and retire the previous transition first')
            previous = record['current'] if record else None
            if family == 'metrics-token' and (record is None or record['current'] is None):
                initial = os.environ.get('IRIS_OBSERVABILITY_TOKEN_FILE')
                old = tier_auth._read(initial, required=False, scope='observability')
                previous = old.decode('utf-8') if old is not None else None
                overlap = tier_auth._read(os.environ.get('IRIS_OBSERVABILITY_PREVIOUS_TOKEN_FILE'), required=False, scope='observability')
                if overlap is not None and overlap != old:
                    raise CredentialError('Retire the deployment-managed scrape overlap before adopting Console management')
            if previous == current:
                raise CredentialError('Replacement must differ from the current credential')
            store.setdefault('service_credentials', {})[family] = dict(request_id=payload['request_id'],
                state='awaiting-verification', started_at=int(time.time()), current=current, previous=previous, endpoint=endpoint,
                previous_managed=bool(record and record['current'] is not None), previous_endpoint=record['endpoint'] if record else None)
        else:
            if not record or record['request_id'] != payload['request_id']:
                raise CredentialError('Credential operation changed; refresh before retiring')
            if action == 'revert':
                if record['state'] == 'reverted':
                    return status()
                if record['state'] != 'awaiting-verification':
                    raise CredentialError('A completed retirement cannot be reverted')
                record.update(current=record['previous'] if record['previous_managed'] else None,
                    endpoint=record['previous_endpoint'] if record['previous_managed'] else None,
                    previous=None, previous_endpoint=None, previous_managed=False, state='reverted')
            elif record['state'] == 'completed':
                return status()
            elif _proof(record, family) is None:
                raise CredentialError('No successful use of this replacement has been observed yet')
            else:
                record.update(previous=None, previous_endpoint=None, previous_managed=False, state='completed')
        secretfs.persist_store(store, path, recipients_csv=recipients, enc_path=encrypted)
    return status()


def metrics_authorized(headers, current_path, previous_path):
    try:
        record = _record(_load(), 'metrics-token')
        if record is None or record['current'] is None:
            return tier_auth.authorized(headers, current_path, previous_path, scope='observability')
        value = tier_auth.bearer(headers) or b''
        current = hmac.compare_digest(value, record['current'].encode())
        previous = hmac.compare_digest(value, (record['previous'] or record['current']).encode())
        return current or (record['previous'] is not None and previous)
    except (CredentialError, tier_auth.CredentialUnavailable):
        return False


def observed_scrape(headers):
    try:
        record = _record(_load(), 'metrics-token')
        if record and record['current'] is not None and hmac.compare_digest(tier_auth.bearer(headers) or b'', record['current'].encode()):
            _observed(record, 'metrics-token')
    except (OSError, ValueError, keys.InstructionKeyError):
        pass  # A failed proof never turns a successful scrape into an error.


def collector_headers(endpoint, fallback):
    record = _record(_load(), 'collector-headers')
    if record is None or record['current'] is None:
        return fallback, None
    if _endpoint(endpoint) != record['endpoint']:
        raise CredentialError('Collector credential is bound to a different HTTPS destination')
    # Rollback preserves the operation ID but changes the effective secret.
    # Include state so the telemetry worker also reloads a reverted override.
    return dict(record['current']), record['request_id'] + ':' + record['state']


def observed_delivery(url, headers):
    try:
        record = _record(_load(), 'collector-headers')
        if (record and record['current'] is not None and url in (record['endpoint'] + '/v1/logs', record['endpoint'] + '/v1/metrics')
                and _headers(headers) == record['current']):
            _observed(record, 'collector-headers')
    except (OSError, ValueError, keys.InstructionKeyError):
        pass
