# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Plan-before-apply uninstall of one recorded installation.

The existing installation and service locks serialize this operation. Each
removal has a durable exact-resource intent. Recovery observes that same target
before continuing; a timeout never means absence. History and private holder
material are retained, including after explicitly purging application volumes.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import uuid

from . import deploy, managed_worker, uninstall_runtime as runtime
from . import upgrade_runtime
from .state import InstallError, Journal, atomic_write, regular_bytes
from .upgrade_plan import canonical, fingerprint, identifier, require, sha256

RECORD = 'uninstall.json'
PHASES = ('prepared', 'fencing', 'removing', 'uninstalled')


def read(base):
    path = base / RECORD
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
            'Unsafe uninstall record; preserve it for recovery')
    value = json.loads(regular_bytes(path, 16 * 1024 * 1024))
    require(isinstance(value, dict) and type(value.get('schema')) is int and value['schema'] == 1 and value.get('phase') in PHASES,
            'Unsupported uninstall record')
    identifier(value.get('operation_id'))
    identifier(value.get('instance_id'))
    plan = value.get('plan')
    require(isinstance(plan, dict) and plan.get('operation_id') == value['operation_id']
            and plan.get('instance_id') == value['instance_id']
            and fingerprint(plan) == value.get('plan_sha256'), 'Uninstall plan changed')
    completed = value.get('completed')
    require(isinstance(completed, list) and all(item in plan['targets'] for item in completed)
            and len({tuple(item) for item in completed}) == len(completed)
            and value.get('pending') in [None, *plan['targets']], 'Uninstall removal progress is invalid')
    view = value.get('removal_view')
    if view is not None:
        require({key: item for key, item in view.items() if key not in ('requests', 'snapshots')}
                == {key: item for key, item in plan.items() if key not in ('requests', 'snapshots')}
                and set(view['requests']) == set(view['snapshots']) == {'kubernetes'},
                'Uninstall stopped topology view changed')
        original_rows = plan['snapshots']['kubernetes']['resources']
        rows = view['snapshots']['kubernetes']['resources']
        require(set(original_rows) <= set(rows) <= set(original_rows) | {'NetworkPolicy/iris-maintenance-isolation'},
                'Uninstall stopped resource set changed')
        for key, row in original_rows.items():
            require(rows[key]['id'] == row['id'] and (key.startswith('Deployment/') or rows[key]['sha256'] == row['sha256']),
                    'Uninstall stopped resource identity changed')
    return value


def save(base, record):
    atomic_write(base / RECORD, canonical(record))


def public(base, record):
    plan = record['plan']
    return {'operation_id': record['operation_id'], 'plan_sha256': record['plan_sha256'],
            'phase': record['phase'], 'plan': str(base / RECORD), 'purge_data': plan['purge_data'],
            'targets': plan['targets'], 'retained': [[location, key]
                for location, snapshot in record.get('removal_view', plan)['snapshots'].items()
                for key in snapshot['resources'] if [location, key] not in plan['targets']],
            'preserves': plan['preserves'],
            'completed': record.get('completed', []), 'pending': record.get('pending')}


def idle(journal):
    from .application_upgrade import _idle
    _idle(journal)
    capture_idle(journal)
    for name in ('kube-update.json', 'worker-custody-intent.json'):
        require(not (journal.directory / name).exists() and not (journal.directory / name).is_symlink(),
                'Finish the pending deployment update before uninstall')


def capture_idle(journal):
    from .backup_capture import guard
    guard(journal.directory, instance_id=journal.document['id'])


def worker_snapshot(base):
    record = managed_worker._load(base)
    managed_worker._check_unit(base, record)
    from .upgrade_boot_guard import describe, _paths
    boot_guard = describe(base, record)
    dropin = None
    if boot_guard:
        _directory, path = _paths(base, record)
        dropin = {'path': str(path), 'sha256': deploy.digest(path)}
    return {'record': record, 'unit_sha256': deploy.digest(managed_worker.UNIT_DIRECTORY / record['unit']),
            'dropin': dropin}


def plan(args):
    managed_worker._root()
    base = managed_worker._path(args.state_dir)
    with managed_worker._service_lock(base):
        worker = worker_snapshot(base)
        with Journal(base).locked() as journal:
            require(journal.document is not None, 'Uninstall requires an existing installation journal')
            require(not (base / RECORD).exists() and not (base / RECORD).is_symlink(),
                    'Inspect or cancel the existing uninstall plan; do not overwrite it')
            idle(journal)
            install = deploy.installation(journal)
            upgrade_runtime.drain(install)
            requests = runtime.discover(install)
            fence_authority = runtime.kube_fence_authority(install)
            snapshots = {}
            targets = []
            retained = []
            # Stop/remove the split Console before its server.
            for location in sorted(requests, key=lambda value: value != 'console'):
                adapter = runtime.driver(install, location, requests[location])
                snapshot = adapter.snapshot()
                snapshots[location] = snapshot
                wanted = runtime.targets(location, snapshot, args.purge_data)
                targets.extend([[location, key] for key in wanted])
                retained.extend([[location, key] for key in snapshot['resources'] if key not in wanted])
                if location != 'kubernetes':
                    expected = {kind + '/' + name for kind, rows in requests[location]['names'].items() for name in rows}
                    require(set(snapshot['resources']) == expected, 'Uninstall needs every recorded Docker resource')
            original = copy.deepcopy(journal.document)
            review = {'schema': 1, 'operation_id': str(uuid.uuid4()), 'instance_id': original['id'],
                      'installation': original, 'worker': worker, 'requests': requests, 'snapshots': snapshots,
                      'kube_fence_authority': fence_authority,
                      'targets': targets, 'retained': retained, 'purge_data': args.purge_data,
                      'preserves': ['installation-history', 'holder-keys', 'backup-and-recovery-storage',
                                    'external-image-root', 'host-packages', 'shared-images', 'namespace',
                                    'local-source-artifacts-and-private-state']}
            record = {'schema': 1, 'operation_id': review['operation_id'], 'instance_id': review['instance_id'],
                      'phase': 'prepared', 'plan': review, 'plan_sha256': fingerprint(review),
                      'completed': [], 'pending': None}
            save(base, record)
            print(json.dumps(public(base, record), sort_keys=True))
            return 0


def check_worker(base, saved, *, unit_may_be_absent=False):
    require(json.loads(managed_worker._file(base / managed_worker.RECORD)) == saved['record'],
            'Uninstall worker identity changed')
    path = managed_worker.UNIT_DIRECTORY / saved['record']['unit']
    if path.exists() or path.is_symlink():
        require(hashlib.sha256(managed_worker._file(path, mode=0o644)).hexdigest() == saved['unit_sha256'],
                'Uninstall worker unit changed')
    else:
        require(unit_may_be_absent, 'Uninstall worker unit disappeared before removal intent')
    directory = path.with_name(path.name + '.d')
    expected = saved['dropin']
    if directory.exists() or directory.is_symlink():
        managed_worker._path(directory)
        require(expected is not None and {p.name for p in directory.iterdir()} <= {Path(expected['path']).name},
                'Uninstall refuses unrecorded systemd drop-ins')
        dropin = Path(expected['path'])
        if dropin.exists() or dropin.is_symlink():
            require(hashlib.sha256(managed_worker._file(dropin, mode=0o644)).hexdigest() == expected['sha256'],
                    'Uninstall worker drop-in changed')
        else:
            require(unit_may_be_absent, 'Worker drop-in disappeared before removal intent')
    elif expected:
        require(unit_may_be_absent, 'Worker drop-in directory disappeared before removal intent')


def worker_stopped(saved):
    raw = managed_worker.command(['systemctl', 'show', saved['record']['unit'],
        '--property=ActiveState,SubState,UnitFileState,MainPID']).decode().splitlines()
    value = dict(line.split('=', 1) for line in raw if '=' in line)
    require(value.get('ActiveState') in ('inactive', 'failed') and value.get('MainPID') == '0'
            and value.get('UnitFileState') in ('disabled', ''),
            'Uninstall worker is not disabled and stopped')
    return value


def expected_snapshot(adapter, plan, location, completed):
    result = adapter.stable(plan['snapshots'][location])
    for target in completed:
        if target[0] == location:
            del result['resources'][target[1]]
    return result


def reconcile(adapter, plan, location, record):
    expected = expected_snapshot(adapter, plan, location, record['completed'])
    observed = adapter.snapshot()
    pending = record['pending']
    if pending and pending[0] == location and pending[1] not in observed['resources']:
        require(pending in plan['targets'] and pending not in record['completed'], 'Invalid pending uninstall target')
        del expected['resources'][pending[1]]
        require(adapter.stable(observed) == expected, 'Unknown removal changed another resource')
        record['completed'].append(pending)
        record['pending'] = None
    else:
        require(adapter.stable(observed) == expected, 'Uninstall resource was changed or replaced')
    return observed


def apply(args, *, recovery=False):
    managed_worker._root()
    base = managed_worker._path(args.state_dir)
    identifier(args.operation_id)
    sha256(args.plan_sha256)
    require(args.allow_downtime, 'Pass --allow-downtime for the reviewed uninstall')
    with managed_worker._service_lock(base):
        with Journal(base).locked(allow_uninstall=True) as journal:
            record = read(base)
            review = record['plan']
            require(record['operation_id'] == args.operation_id and record['plan_sha256'] == args.plan_sha256
                    and record['instance_id'] == journal.document['id'], 'Uninstall approval selects another operation')
            require(review['purge_data'] is args.purge_data, 'Repeat the exact reviewed --purge-data choice')
            kube_fencing = (review['kube_fence_authority'] is not None and record['phase'] == 'fencing')
            require(kube_fencing or journal.document == record.get('fenced_installation', review['installation']),
                    'Installation journal changed after uninstall review')
            require(recovery or record['phase'] == 'prepared', 'Use recover for the original interrupted uninstall')
            if record['phase'] == 'uninstalled':
                print(json.dumps(public(base, record), sort_keys=True))
                return 0
            capture_idle(journal)
            install = deploy.installation(journal)
            install.verify_inputs()
            if kube_fencing:
                runtime.check_kube_fence_journal(install, review['installation'], review['kube_fence_authority'])
            elif review['kube_fence_authority'] is not None and record['phase'] == 'removing':
                runtime.check_kube_fence_journal(install, review['installation'], review['kube_fence_authority'], recover=False)
            check_worker(base, review['worker'], unit_may_be_absent=record.get('worker_remove_intent') is True)
            view = record.get('removal_view', review)
            adapters = {location: runtime.driver(install, location, request)
                        for location, request in view['requests'].items()}
            if not kube_fencing:
                for location, adapter in adapters.items():
                    reconcile(adapter, view, location, record)
            save(base, record)
            if record['phase'] == 'prepared':
                idle(journal)
                upgrade_runtime.drain(install)
                record['phase'] = 'fencing'
                save(base, record)
            if record['phase'] == 'fencing':
                saved = review['worker']
                managed_worker.command(['systemctl', 'disable', saved['record']['unit']])
                managed_worker.command(['systemctl', 'stop', saved['record']['unit']], timeout=3600)
                record['worker_stopped'] = worker_stopped(saved)
                upgrade_runtime.jobs_idle(base)
                if review['kube_fence_authority'] is not None:
                    requests = runtime.fence_kubernetes(install, review['installation'], review['kube_fence_authority'])
                    adapters = {location: runtime.driver(install, location, request) for location, request in requests.items()}
                    snapshots = {location: adapter.snapshot() for location, adapter in adapters.items()}
                    require(not snapshots['kubernetes']['pods'], 'Kubernetes writer fence still has pods')
                    view = dict(review, requests=requests, snapshots=snapshots)
                    # The maintenance policy has a fixed producer definition and
                    # remains in the retained namespace; it is not a new purge target.
                    record['removal_view'] = view
                    record['fenced_installation'] = copy.deepcopy(journal.document)
                else:
                    for location, adapter in adapters.items():
                        snapshot = reconcile(adapter, review, location, record)
                        for key in sorted(snapshot['resources']):
                            if key.startswith('container/'):
                                record['stop_intent'] = [location, key]
                                save(base, record)
                                snapshot = adapter.stop(key, adapter.stable(snapshot))
                    from .trust_maintenance import _stopped
                    _stopped(install)
                    upgrade_runtime.drain(install, stopped=True)
                record.pop('stop_intent', None)
                record['stopped_drain_verified'] = True
                record['phase'] = 'removing'
                save(base, record)
            capture_idle(journal)
            require(record.get('stopped_drain_verified') is True, 'Stopped device-removal proof is missing')
            if not record.get('worker_remove_intent'):
                worker_stopped(review['worker'])
            for target in review['targets']:
                if target in record['completed']:
                    continue
                require(record['pending'] in (None, target), 'Recover the original pending removal first')
                location, key = target
                adapter = adapters[location]
                reconcile(adapter, view, location, record)
                record['pending'] = target
                save(base, record)
                adapter.remove(key, expected_snapshot(adapter, view, location, record['completed']))
                reconcile(adapter, view, location, record)
                require(target in record['completed'], 'Removal is not independently absent')
                save(base, record)
            for location, adapter in adapters.items():
                observed = reconcile(adapter, view, location, record)
                require(location != 'kubernetes' or not observed['pods'], 'Owned Kubernetes pods still exist')
            # Delete only captured service definition bytes. Keep pinned runtime,
            # records, all private keys and backups for inspection or recovery.
            record['worker_remove_intent'] = True
            save(base, record)
            check_worker(base, review['worker'], unit_may_be_absent=True)
            unit = managed_worker.UNIT_DIRECTORY / review['worker']['record']['unit']
            dropin = review['worker']['dropin']
            if dropin:
                path = Path(dropin['path'])
                if path.exists():
                    path.unlink()
                if path.parent.exists():
                    path.parent.rmdir()
            if unit.exists():
                unit.unlink()
            from .restore_storage import sync
            sync(managed_worker.UNIT_DIRECTORY)
            managed_worker.command(['systemctl', 'daemon-reload'])
            require(not unit.exists() and not unit.is_symlink(), 'Worker unit remains after uninstall')
            raw = managed_worker.command(['systemctl', 'show', unit.name, '--property=LoadState,ActiveState,MainPID']).decode()
            fields = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
            require(fields.get('LoadState') == 'not-found' and fields.get('ActiveState') == 'inactive'
                    and fields.get('MainPID') == '0', 'Worker service is not independently absent')
            record['phase'] = 'uninstalled'
            save(base, record)
            print(json.dumps(public(base, record), sort_keys=True))
            return 0


def status(args):
    managed_worker._root()
    base = managed_worker._path(args.state_dir)
    with Journal(base).locked(allow_uninstall=True):
        print(json.dumps(public(base, read(base)), sort_keys=True))
    return 0


def cancel(args):
    managed_worker._root()
    base = managed_worker._path(args.state_dir)
    with managed_worker._service_lock(base), Journal(base).locked() as journal:
        record = read(base)
        require(record['phase'] == 'prepared' and record['operation_id'] == args.operation_id
                and record['plan_sha256'] == args.plan_sha256 and record['instance_id'] == journal.document['id'],
                'Only the exact unapplied uninstall plan can be cancelled')
        destination = base / ('uninstall-cancelled-' + identifier(args.operation_id) + '.json')
        require(not destination.exists() and not destination.is_symlink(), 'Cancelled plan history already exists')
        os.rename(base / RECORD, destination)
        from .restore_storage import sync
        sync(base)
        print(json.dumps({'operation_id': args.operation_id, 'phase': 'cancelled', 'history': str(destination)}))
    return 0
