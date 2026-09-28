# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Typed local maintenance RPC; never forwards browser-supplied paths or commands."""

import json
import os
import re
import socket


class LifecycleUnavailable(Exception):
    pass


ROTATION_FAMILIES = ('management-tls', 'device-tls', 'peer-ca',
                     'instruction-roots', 'age-identity', 'age-recovery', 'seeder-announce')


def call(request):
    if not isinstance(request, dict):
        raise ValueError('Expected a maintenance request')
    action = request.get('action')
    fields = {'status': {'action'}, 'rotation-status': {'action'},
              'rotate': {'action', 'request_id', 'family', 'allow_downtime'},
              'recover-rotation': {'action', 'request_id', 'family', 'allow_downtime'},
              'backup': {'action', 'request_id', 'allow_downtime'},
              'verify': {'action', 'request_id', 'backup_id'}, 'extract': {'action', 'request_id', 'backup_id'}}
    if not isinstance(action, str) or action not in fields or set(request) != fields[action]:
        raise ValueError('Unsupported maintenance request')
    if action not in ('status', 'rotation-status') and (not isinstance(request['request_id'], str)
            or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', request['request_id'])):
        raise ValueError('Provide a bounded maintenance request ID')
    if action in ('backup', 'rotate', 'recover-rotation') and request['allow_downtime'] is not True:
        raise ValueError('Confirm IRIS downtime before capture')
    if action in ('rotate', 'recover-rotation') and request['family'] not in ROTATION_FAMILIES:
        raise ValueError('Choose a supported credential family')
    if action in ('verify', 'extract') and (not isinstance(request['backup_id'], str)
            or not re.fullmatch(r'[0-9a-f-]{36}', request['backup_id'])):
        raise ValueError('Choose a captured backup')
    endpoint = os.environ.get('IRIS_LIFECYCLE_SOCKET', '/run/iris-lifecycle/control.sock')
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect(endpoint)
            connection.sendall(json.dumps(request).encode() + b'\n')
            with connection.makefile('rb') as stream:
                raw = stream.readline(128 * 1024 + 1)
            if len(raw) > 128 * 1024 or not raw.endswith(b'\n'):
                raise ValueError('Invalid worker response')
            response = json.loads(raw)
            if not isinstance(response, dict) or type(response.get('ok')) is not bool:
                raise ValueError('Invalid worker response')
    except (OSError, ValueError):
        raise LifecycleUnavailable('Deployment lifecycle worker unavailable. Configure it on the installer host.') from None
    if not response['ok']:
        # Worker messages are fixed safe validation text, not raw command logs.
        raise LifecycleUnavailable(response.get('error', 'Maintenance request refused'))
    return response['result']


def status():
    try:
        return call({'action': 'status'})
    except LifecycleUnavailable:
        return {'available': False, 'target': 'unavailable', 'storage': 'unavailable',
                'can_verify': False, 'can_extract': False, 'jobs': [],
                'note': 'Configure the lifecycle worker on the installer host. No backup or recovery verification is attested.'}


def rotation_status():
    try:
        return call({'action': 'rotation-status'})
    except LifecycleUnavailable:
        return {'available': False, 'target': 'unavailable', 'can_rotate': False,
                'families': [], 'jobs': [],
                'note': 'Configure the deployment worker and independent recovery access before rotation.'}
