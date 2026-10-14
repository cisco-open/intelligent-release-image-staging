# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Exact Docker and systemd boundaries used by the application upgrade journal."""

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace

from . import backup, backup_archive, deploy, managed_worker, restore, restore_storage as storage
from . import upgrade_plan as plan
from .state import InstallError, atomic_write, regular_bytes


def equal(left, right):
    return plan.canonical(left) == plan.canonical(right)


def worker_state(base):
    record = managed_worker._load(base)
    managed_worker._check_unit(base, record)
    managed_worker.check_storage(base, record)
    plan.require(record.get('phase') == 'ready' and record.get('recovery_identity'),
                 'A ready managed worker with recovery access is required for upgrade')
    output = managed_worker.command(['systemctl', 'show', record['unit'],
        '--property=ActiveState,SubState,UnitFileState']).decode().splitlines()
    observed = dict(line.split('=', 1) for line in output if '=' in line)
    plan.require(observed.get('ActiveState') == 'active' and observed.get('SubState') == 'running'
                 and observed.get('UnitFileState') == 'enabled',
                 'Start and enable the recorded healthy worker before preparing an upgrade')
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
                 'Finish or recover active lifecycle work before upgrading')
    # No other family's boot-time mutation may run during the handoff.
    pending = base / 'worker-custody-intent.json'
    plan.require(not pending.exists() and not pending.is_symlink(),
                 'Finish managed-worker recovery before upgrading')


def drain(install, *, stopped=False):
    code = ('import trust_rotation,json; r=trust_rotation.drain_status(); '
            'print(json.dumps({"ready":r["ready"],"removed_count":len(r["removed_device_ids"])}))')
    if stopped:
        from .trust_maintenance import _one_shot
        value = json.loads(_one_shot(install, code))
    else:
        value = json.loads(install.python(code))
    plan.require(isinstance(value, dict) and value.get('ready') is True,
                 'Undeploy every IRIS device and wait for confirmed removal before upgrading; keep inventory')
    return value


def fence_worker(base, saved, *, new_runtime=None):
    actual = managed_worker._load(base)
    old = equal(actual, saved['record'])
    if not old:
        plan.require(new_runtime is not None and equal(actual.get('runtime'), new_runtime),
                     'The reviewed worker generation changed')
        expected = copy.deepcopy(saved['record'])
        for key in ('runtime', 'phase', 'previous_unit_sha256'):
            expected.pop(key, None)
        observed = {key: value for key, value in actual.items()
                    if key not in ('runtime', 'phase', 'previous_unit_sha256')}
        plan.require(equal(observed, expected) and actual.get('phase') in
                     ('runtime-update', 'service-written', 'ready'), 'The worker custody changed during recovery')
    unit = managed_worker._file(managed_worker.UNIT_DIRECTORY / actual['unit'], mode=0o644)
    plan.require(hashlib.sha256(unit).hexdigest() == saved['unit_sha256'] or
                 (not old and unit == managed_worker.unit_bytes(base, actual)),
                 'The reviewed worker unit changed')
    # Intent is persisted by the caller before both commands. Disabling first
    # closes the reboot window even if the graceful stop is interrupted.
    managed_worker.command(['systemctl', 'disable', actual['unit']])
    managed_worker.command(['systemctl', 'stop', actual['unit']], timeout=3600)
    observed = managed_worker.command(['systemctl', 'show', actual['unit'],
        '--property=ActiveState,UnitFileState']).decode().splitlines()
    fields = dict(line.split('=', 1) for line in observed if '=' in line)
    plan.require(fields.get('ActiveState') in ('inactive', 'failed')
                 and fields.get('UnitFileState') == 'disabled', 'The previous worker is not safely fenced')
    jobs_idle(base)
    return fields


def disable_restarts(install, containers):
    for container in containers:
        if container.get('remote'):
            plan.require(install.config['target'] == 'docker-split', 'Unexpected remote upgrade writer')
            # The operation-specific inherited remote lock and exact Console
            # identity were fenced before this local-only boundary.
            from .upgrade_split import remote
            row = remote(install, install.upgrade_operation, 'observe')
            plan.require(row['Id'] == container['id'] and row['State']['Running'] is False
                         and row['HostConfig']['RestartPolicy']['Name'] == 'no',
                         'The reviewed remote Console is not fenced')
            continue
        rows = json.loads(install.command(['docker', 'inspect', container['id']], capture=True))
        plan.require(len(rows) == 1 and rows[0]['Id'] == container['id']
                     and rows[0]['Config'].get('Labels', {}).get('com.cisco.iris.installer') == install.journal.document['id'],
                     'A reviewed container was replaced before fencing')
        install.command(['docker', 'update', '--restart=no', container['id']])
        observed = json.loads(install.command(['docker', 'inspect', container['id']], capture=True))[0]
        plan.require(observed['HostConfig']['RestartPolicy']['Name'] == 'no',
                     'Container restart policy did not enter the fenced state')


def verify_images(install, images):
    for image in images.values():
        rows = json.loads(install.command(['docker', 'image', 'inspect', image], capture=True))
        plan.require(len(rows) == 1 and rows[0]['Id'] == image,
                     'An approved immutable application image is missing')


def verify_files(directory, manifest, *, closed=False):
    if closed:
        expected_directories = {str(parent) for name in manifest for parent in Path(name).parents}
        for path in directory.rglob('*'):
            name = str(path.relative_to(directory))
            plan.require(not path.is_symlink() and
                (path.is_file() and name in manifest or path.is_dir() and name in expected_directories),
                'The approved source contains an extra or linked input')
    for name, expected in plan.file_manifest(manifest).items():
        path = directory / name
        plan.require(path.resolve() == path and path.is_file() and path.stat().st_nlink == 1
                     and deploy.digest(path) == expected, 'An approved upgrade input changed: ' + name)


def capture_and_verify(base, operation, saved_worker):
    """A failed or interrupted capture is retained, never restored over live data."""
    record = saved_worker['record']
    attempts = operation.record.setdefault('backup_attempts', [])
    if attempts:
        candidate = attempts[-1]
        paths = [Path(candidate[name]) for name in ('data', 'identity')]
        if all(all((path / name).is_file() for name in
                   ('manifest.json', 'manifest.json.sig', 'payload.tar.age')) for path in paths):
            return verify_backup(base, candidate, record)
    plan.require(len(attempts) < 3, 'Three capture attempts are retained; inspect backup custody before continuing')
    suffix = 'upgrade-' + operation.id + '-' + str(len(attempts) + 1)
    candidate = {name: str(Path(record['storage'][kind]['directory']) / suffix)
                 for name, kind in (('data', 'backup'), ('identity', 'recovery'))}
    plan.require(all(not Path(value).exists() and not Path(value).is_symlink() for value in candidate.values()),
                 'An unrecorded upgrade backup path already exists')
    attempts.append(candidate)
    operation.save()
    backup.create(SimpleNamespace(state_dir=base, output=Path(candidate['data']),
        recovery_output=Path(candidate['identity']), allow_downtime=True,
        application_upgrade_id=operation.id))
    return verify_backup(base, candidate, record)


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


def stage_artifacts(install, operation, candidate):
    original = install.base / 'artifacts'
    staged = install.base / ('.upgrade-artifacts-' + operation.id)
    if 'artifact_before' not in operation.record:
        operation.record['artifact_before'] = storage.inventory(original)
        operation.save()
    before = operation.record['artifact_before']
    plan.require(storage.inventory(original) == before, 'Served artifacts changed after stopped admission')
    if 'artifact_after' in operation.record:
        plan.require(storage.inventory(staged) == operation.record['artifact_after'],
                     'The staged artifact candidate changed')
        return
    storage.candidate(original, staged, before)
    source = Path(candidate['artifacts_directory'])
    verify_files(source, candidate['files'])
    for name in candidate['files']:
        path = staged / name
        # Only approved generated files are replaced in the private candidate.
        # Runtime certificates and every unrelated public artifact remain.
        shutil.copyfile(source / name, path)
        path.chmod(0o644)
        os.chown(path, 10001, 10001)
        with path.open('rb') as stream:
            os.fsync(stream.fileno())
    operation.record['artifact_after'] = storage.inventory(staged)
    operation.save()
    storage.sync(staged)


def authority(install, sources):
    """Record hashes only; no private bytes leave deployment custody.

    Ciphertext may be re-encrypted during startup, so secrets use a hash of the
    decrypted canonical object. All other configuration, including unknown
    fields and key/certificate files, must remain byte-identical. Audit lines
    may append normally; no archived configuration is copied into live storage.
    """
    from .trust_maintenance import _one_shot
    restore._producer_proof(install)
    code = '''
import hashlib,json,os,tempfile
import secretfs,secrets_store
with tempfile.TemporaryDirectory(dir=os.environ.get('IRIS_RUN','/run/iris')) as d:
 p=os.path.join(d,'upgrade-secrets.json')
 secretfs.decrypt_to(os.path.join(os.environ.get('IRIS_CONFIG','/etc/iris'),'secrets.json.age'),p,os.environ['IRIS_AGE_KEY_FILE'])
 value=secrets_store.load(p,require_existing=True)
 if not isinstance(value.get('admin'),dict) or not value['admin'].get('username'): raise RuntimeError('existing owner required')
 print(json.dumps({'owner_and_secrets_sha256':hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()}))
'''
    secrets = json.loads(_one_shot(install, code))
    plan.sha256(secrets.get('owner_and_secrets_sha256'))
    config = sources['volume-iris-config']
    records = {path.name: storage.fingerprint(storage.inventory(path))
               for path in sorted(config.iterdir()) if path.name not in ('audit.jsonl', 'secrets.json.age')}
    state = sources['volume-iris-state']
    prefixes = ('instructions', 'peer-policy', 'deployment_records', 'ca-trust-settings',
                'audit-export-', 'telemetry-destination', 'instance-id', 'schedules.',
                'peer-handouts', 'schedule-progress', 'schedule-retired', 'schedule-occurrences',
                'schedule-receipts', 'report_ledger', 'report-attribution', 'transfer-attestations', 'fleet')
    preserved = {path.name: storage.fingerprint(storage.inventory(path))
                 for path in sorted(state.iterdir()) if path.name.startswith(prefixes)}
    result = {'config_sha256': plan.fingerprint(records), 'authority': preserved, **secrets,
              'age_identity_sha256': deploy.digest(install.base / 'age.txt')}
    if install.config['target'] == 'docker-split':
        from .upgrade_split import remote
        # The reconstructed management public certificate has its own exact
        # same-key publication journal. Private/browser/bearer authority does
        # not receive a wildcard exception from that public-only transition.
        result['remote_credentials'] = {name: value for name, value in
            remote(install, install.upgrade_operation, 'credentials').items() if name != 'ca.pem'}
        result['transport'] = install.transport_fingerprints()
    return result


def refresh_worker(base, operation, reviewed):
    """Update through the installed worker machinery, retaining exact custody."""
    current = managed_worker._load(base)
    before = copy.deepcopy(reviewed['record'])
    expected_runtime = operation.record['candidate']['selection']['runtime']
    plan.require(equal(managed_worker._runtime_manifest(), expected_runtime),
                 'The installed maintenance runtime changed after upgrade approval')
    for name in ('instance_id', 'target', 'state_dir', 'lifecycle_url', 'listen_address',
                 'recovery_identity', 'recovery_identity_source', 'storage_layout', 'storage'):
        plan.require(equal(current.get(name), before.get(name)), 'Worker custody changed during upgrade')
    plan.require(equal(current.get('runtime'), before['runtime']) or equal(current.get('runtime'), expected_runtime),
                 'The worker has an unapproved runtime generation')
    managed_worker._setup(SimpleNamespace(state_dir=base, refresh_runtime=True,
        application_upgrade_id=operation.id, backup_root=None, recovery_root=None,
        recovery_identity=None, listen_address=None))
    result = managed_worker._load(base)
    plan.require(equal(result['runtime'], expected_runtime), 'Worker did not adopt the approved runtime')
    proof = managed_worker.inspect(base)
    plan.require(all(proof.get(name) is True for name in
                     ('managed', 'active', 'enabled', 'storage_ready', 'unix_ready')),
                 'The approved new worker is not healthy and ready')
    return proof
