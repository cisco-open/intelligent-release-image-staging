# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Public evidence for host-owned, same-key signing certificate renewal."""

import json
import os
import time

import instruction_keys as keys

DAY = 86400
STATUS_NAME = 'signing-renewal-status.json'
STATES = {'disabled', 'waiting', 'renewing', 'renewed', 'error', 'review-required'}


def readiness(*, paths=None, now=None):
    """Signing readiness is separate from listener/container health."""
    paths = paths or keys.InstructionPaths.from_env()
    now = int(time.time()) if now is None else now
    custody = keys.read_status_file(paths.status, now=now)
    producer = None
    try:
        producer = json.loads(keys._read_regular(
            os.path.join(paths.state_dir, 'instruction-stamper-status.json'), 16384,
            unavailable='producer status unavailable', too_large='producer status too large'))
    except (keys.InstructionKeyError, ValueError, OSError):
        pass
    signing = (isinstance(custody, dict) and custody.get('enabled') is True
               and custody.get('signing_refused') is False
               and custody.get('state') in ('ready', 'renewal_due', 'keylist_missing'))
    producing = (isinstance(producer, dict) and producer.get('state') == 'ok'
                 and type(producer.get('updated_at')) is int
                 and 0 <= now - producer['updated_at'] <= 180
                 and isinstance(producer.get('counts'), dict)
                 and producer.get('counts', {}).get('failed') == 0)
    return {'ready': bool(signing and producing), 'signing_ready': bool(signing),
            'producer_ready': bool(producing),
            'custody_state': custody.get('state') if isinstance(custody, dict) else 'unavailable',
            'observed_at': now}


def snapshot(*, paths=None):
    """Only public bytes cross the container/holder boundary."""
    from certificate_lifecycle import inventory
    paths = paths or keys.InstructionPaths.from_env()
    before = keys.online_renewal_request(paths)
    rows = inventory(paths=paths)['items']
    certificate = next(row for row in rows if row['id'] == 'instruction-signer')
    after = keys.online_renewal_request(paths)
    if before != after or certificate['expires_at'] is None or certificate['valid_from'] is None:
        raise keys.InstructionKeyError('Signing identity changed or certificate dates are unavailable')
    return {'request': after, 'roots': {name: value.decode('ascii')
            for name, value in keys.discover_roots(paths).items()},
            'valid_from': certificate['valid_from'], 'expires_at': certificate['expires_at'],
            'renew_at': certificate['renew_at'], 'refuse_at': certificate['refuse_at'],
            'readiness': readiness(paths=paths)}


def validate_status(value):
    fields = {'schema', 'enabled', 'state', 'checked_at', 'renew_at', 'expires_at',
              'refuse_at', 'last_success_at'}
    if (not isinstance(value, dict) or set(value) != fields or type(value['schema']) is not int or value['schema'] != 1
            or type(value['enabled']) is not bool or value['state'] not in STATES
            or any(value[key] is not None and (type(value[key]) is not int or value[key] < 0)
                   for key in fields - {'schema', 'enabled', 'state'})):
        raise keys.InstructionKeyError('Invalid automatic renewal status')
    return value


def attention(*, paths=None, now=None):
    paths = paths or keys.InstructionPaths.from_env()
    ready = readiness(paths=paths, now=now)
    automatic = status(paths=paths, now=now)
    if not ready['signing_ready']:
        message = 'Instruction signing is unavailable. Check Certificates & keys before onboarding.'
    elif not ready['producer_ready']:
        message = 'The instruction producer is not ready. New onboarding may fail.'
    elif automatic['enabled'] and (not automatic['observed'] or automatic['state'] in ('error', 'review-required')):
        message = 'Automatic signing renewal needs attention. Check the host renewal service before the signing cutoff.'
    else:
        custody = keys.read_status_file(paths.status, now=now)
        if isinstance(custody, dict) and custody.get('certificate_renewal_due') and not automatic['enabled']:
            message = 'Renew the signing certificate before the cutoff to keep onboarding available.'
        else:
            return None
    return {'message': message, 'href': '#settings/certificates'}


def publish_status(value, *, paths=None):
    paths = paths or keys.InstructionPaths.from_env()
    keys._atomic_write_json(os.path.join(paths.state_dir, STATUS_NAME), validate_status(value))


def status(*, paths=None, now=None):
    paths = paths or keys.InstructionPaths.from_env()
    now = int(time.time()) if now is None else now
    try:
        value = validate_status(json.loads(keys._read_regular(
            os.path.join(paths.state_dir, STATUS_NAME), 4096,
            unavailable='renewal status unavailable', too_large='renewal status too large')))
    except (keys.InstructionKeyError, ValueError, OSError):
        return {'enabled': False, 'state': 'unconfigured', 'observed': False}
    value = dict(value)
    value['observed'] = (value['checked_at'] is not None
                         and 0 <= now - value['checked_at'] <= 26 * 3600)
    return value
