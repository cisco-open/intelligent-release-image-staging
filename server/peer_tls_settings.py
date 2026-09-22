# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Persistent swarm mode and observed origin status; no certificate material."""
import functools
import json
import os
from pathlib import Path
import tempfile
import threading
import time

MODES = ('disabled', 'required')
LOCK = threading.RLock()


def serialized(fn):
    @functools.wraps(fn)
    def call(*args, **kwargs):
        with LOCK:
            return fn(*args, **kwargs)
    return call


def settings_path():
    return Path(os.environ.get('IRIS_CONFIG', '/etc/iris')) / 'peer-tls-mode.json'


def status_path():
    return Path(os.environ.get('IRIS_RUN', '/run/iris')) / 'peer-tls-status.json'


def mode():
    try:
        with settings_path().open() as stream:
            data = json.loads(stream.read(4097))
        if not isinstance(data, dict) or set(data) != {'mode'}:
            raise ValueError('invalid peer TLS settings')
        value = data['mode']
    except FileNotFoundError:
        value = os.environ.get('IRIS_PEER_TLS_MODE', 'disabled')
    if value not in MODES:
        raise ValueError('invalid peer TLS mode')
    return value


def atomic_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.' + path.name, dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        directory = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def save(value):
    if value not in MODES:
        raise ValueError('invalid peer TLS mode')
    atomic_json(settings_path(), {'mode': value})


def origin_status():
    unavailable = {'active_mode': None, 'state': 'unavailable'}
    try:
        data = json.loads(status_path().read_text())
        if (not isinstance(data, dict) or data.get('active_mode') not in (*MODES, None) or
                data.get('state') not in ('starting', 'running', 'error', 'stopped') or
                not 0 <= time.time() - data['updated_at'] < 30):
            return unavailable
        return {key: data[key] for key in ('active_mode', 'state')}
    except (OSError, ValueError, TypeError, KeyError):
        return unavailable


def describe(records, onboard, fleet=None):
    # Deployment history outlives inventory membership. An orphaned record
    # must not strand the operator behind a device they cannot undeploy.
    members = set() if fleet is None else {d['device_id'] for d in fleet.list_devices()}
    active = [] if records is None else [r for r in records.list(strict=True)
             if r['device_id'] in members and
             r['state'] not in ('removed', 'superseded', 'abandoned')]
    jobs = [] if onboard is None else onboard.list_jobs()
    active_jobs = sum(j['state'] in ('queued', 'running') for j in jobs)
    origin = origin_status()
    return {'mode': mode(), 'origin': origin,
            'active_devices': len({r['device_id'] for r in active}),
            'active_jobs': active_jobs,
            'can_change': fleet is not None and records is not None and onboard is not None and
                          not active and not active_jobs and origin['state'] != 'unavailable'}
