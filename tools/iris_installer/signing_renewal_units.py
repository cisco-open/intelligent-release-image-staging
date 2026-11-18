# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Exact host renewal-unit ownership for reviewed uninstall operations."""
import hashlib

from . import managed_worker, signing_renewal as renewal
from .state import InstallError

BINDING = ('instance_id', 'state_dir', 'root_key', 'holder_uid', 'runtime',
           'public_key_sha256', 'root_public')


def snapshot(base, identifier, *, absent=False):
    path = base / renewal.RECORD
    if not path.exists() and not path.is_symlink():
        for suffix in ('.service', '.timer'):
            unit = renewal.UNITS / ('iris-signing-renewal-' + identifier + suffix)
            if unit.exists() or unit.is_symlink():
                raise InstallError('Renewal units have no matching enrollment')
        return None
    record = renewal.checked_record(base, identifier)
    units = {}
    for name, expected in renewal.unit_files(record).items():
        path = renewal.UNITS / name
        dropins = path.with_name(path.name + '.d')
        if dropins.exists() or dropins.is_symlink():
            raise InstallError('Renewal unit has unreviewed drop-ins')
        if path.exists() or path.is_symlink():
            if managed_worker._file(path, mode=0o644) != expected:
                raise InstallError('Renewal unit changed; preserve it for review')
        elif not absent:
            raise InstallError('Renewal unit disappeared before removal intent')
        units[name] = hashlib.sha256(expected).hexdigest()
    return {'binding': {key: record[key] for key in BINDING}, 'units': units}


def check(base, identifier, saved, *, absent=False):
    if snapshot(base, identifier, absent=absent) != saved:
        raise InstallError('Renewal enrollment changed after uninstall review')


def stop(saved):
    if saved is None:
        return
    for name in sorted(saved['units'], key=lambda name: not name.endswith('.timer')):
        if name.endswith('.timer'):
            managed_worker.command(['systemctl', 'disable', '--now', name])
        else:
            managed_worker.command(['systemctl', 'stop', name])
        raw = managed_worker.command(['systemctl', 'show', name, '--property=ActiveState,MainPID'])
        fields = dict(line.split('=', 1) for line in raw.decode().splitlines() if '=' in line)
        if fields.get('ActiveState') not in ('inactive', 'failed') or fields.get('MainPID', '0') != '0':
            raise InstallError('Renewal unit is not stopped')


def remove(base, identifier, saved):
    check(base, identifier, saved, absent=True)
    if saved is None:
        return
    for name in saved['units']:
        (renewal.UNITS / name).unlink(missing_ok=True)
    from .restore_storage import sync
    sync(renewal.UNITS)
    managed_worker.command(['systemctl', 'daemon-reload'])
    for name in saved['units']:
        raw = managed_worker.command(['systemctl', 'show', name, '--property=LoadState,ActiveState,MainPID'])
        fields = dict(line.split('=', 1) for line in raw.decode().splitlines() if '=' in line)
        if (fields.get('LoadState') != 'not-found' or fields.get('ActiveState') != 'inactive'
                or fields.get('MainPID', '0') != '0'):
            raise InstallError('Renewal unit is not independently absent')
