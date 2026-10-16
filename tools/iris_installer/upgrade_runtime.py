# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Read-only lifecycle prerequisites and historical backup validation.

Shared uninstall and retained worker guards use these checks. Application
replacement, candidate builds and upgrade execution are not supported.
"""

import hashlib
import json
from pathlib import Path

from . import backup_archive, managed_worker, restore
from . import upgrade_plan as plan
from .state import regular_bytes


def equal(left, right):
    return plan.canonical(left) == plan.canonical(right)


def worker_state(base):
    record = managed_worker._load(base)
    managed_worker._check_unit(base, record)
    managed_worker.check_storage(base, record)
    plan.require(record.get('phase') == 'ready' and record.get('recovery_identity'),
                 'A ready managed worker with recovery access is required')
    output = managed_worker.command(['systemctl', 'show', record['unit'],
        '--property=ActiveState,SubState,UnitFileState']).decode().splitlines()
    observed = dict(line.split('=', 1) for line in output if '=' in line)
    plan.require(observed.get('ActiveState') == 'active' and observed.get('SubState') == 'running'
                 and observed.get('UnitFileState') == 'enabled',
                 'Start and enable the recorded healthy worker before maintenance')
    unit = managed_worker._file(managed_worker.UNIT_DIRECTORY / record['unit'], mode=0o644)
    from .upgrade_boot_guard import describe
    return {'record': record, 'unit_sha256': hashlib.sha256(unit).hexdigest(),
            'unit': unit.decode('utf-8'), 'systemd': observed, 'boot_guard': describe(base, record)}


def jobs_idle(base):
    from .lifecycle_history import guard as retention_guard
    retention_guard(base)
    path = base / 'lifecycle-jobs.json'
    rows = json.loads(regular_bytes(path, 16 * 1024 * 1024)) if path.exists() else []
    plan.require(isinstance(rows, list) and all(isinstance(row, dict) for row in rows)
                 and not any(row.get('state') in ('running', 'queued', 'recovery-required') for row in rows),
                 'Finish or recover active lifecycle work before removal')
    # No other family's boot-time mutation may run during the handoff.
    pending = base / 'worker-custody-intent.json'
    plan.require(not pending.exists() and not pending.is_symlink(),
                 'Finish managed-worker recovery before removal')


def drain(install, *, stopped=False):
    code = ('import trust_rotation,json; r=trust_rotation.drain_status(); '
            'print(json.dumps({"ready":r["ready"],"removed_count":len(r["removed_device_ids"])}))')
    if stopped:
        from .trust_maintenance import _one_shot
        value = json.loads(_one_shot(install, code))
    else:
        value = json.loads(install.python(code))
    plan.require(isinstance(value, dict) and value.get('ready') is True,
                 'Undeploy every IRIS device and wait for confirmed removal before removing the deployment; keep inventory')
    return value


def verify_backup(base, candidate, worker):
    identity = Path(worker['recovery_identity'])
    signer = restore.custody(base, identity)
    reports = {name: backup_archive.read(Path(path), identity, signer) for name, path in candidate.items()}
    data, recovery = reports['data'], reports['identity']
    # read() returns the authenticated manifest metadata in its evidence.
    for name, report in reports.items():
        metadata = report.get('metadata', {})
        plan.require(metadata.get('instance_id') == worker['instance_id']
                     and metadata.get('target') == {'docker': 'single-docker', 'docker-split': 'split-docker'}.get(worker['target'])
                     and metadata.get('scope') == ('managed-deployment-files' if name == 'data' else 'identity-recovery'),
                     'The decrypted upgrade backup belongs to another deployment')
        plan.identifier(metadata.get('backup_set_id'))
    plan.require(data['metadata']['backup_set_id'] == recovery['metadata']['backup_set_id'],
                 'Upgrade backup and identity sets do not belong together')
    return {'paths': candidate, 'proof': reports}
