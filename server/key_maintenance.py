# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Opt-in UTC key maintenance, with explicit custody and consumer boundaries.

The journal contains public operation identities, never credentials. A durable
running intent is not retried automatically after an uncertain result. Missing
windows are recorded, not replayed as a burst of credential changes.
"""

from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import stat
import time
import uuid

import instruction_keys as keys
import instruction_rotation
import instruction_stamper
import instructions
import secretfs
import secrets_store
import tier_auth

DAY = 86400
FAMILIES = {
    'online-signer': ('Online instruction signer', 'prepare', 'Offline certificate and retirement approvals', 'admin-guide/signer-rotation/'),
    'device-instruction': ('Device instruction encryption key', 'rotate', 'Seven-day overlap; verify device acceptance', 'admin-guide/rotations/#rotate-one-devices-instruction-key'),
    'management-token': ('Console management credential', 'rotate', 'Verify all Console instances before retiring overlap', 'admin-guide/rotations/#rotate-the-management-credential'),
    'browser-tls': ('Console browser TLS', 'review', 'Public request, approval and listener verification in Certificates & keys', 'admin-guide/console-credentials/#replace-the-browser-certificate'),
    'management-tls': ('Management TLS', 'review', 'Stage Console trust, replace server pair, verify listeners', 'admin-guide/rotations/#rotate-the-management-certificate'),
    'device-tls': ('Device-pinned TLS', 'review', 'Device trust rollout and re-onboarding', 'admin-guide/rotations/#rotate-the-certificate-that-devices-trust'),
    'peer-ca': ('Private swarm issuing CA', 'review', 'Coordinated trust rollout; distinct from automatic leaf renewal', 'admin-guide/rotations/'),
    'offline-roots': ('Offline signing roots', 'review', 'Independent custodians and device trust rollout', 'admin-guide/instruction-keys/'),
    'age-identity': ('Encryption-at-rest identity and recipients', 'review', 'Protected backup, stopped writers and decryption proof', 'admin-guide/rotations/#rotate-the-age-recipients'),
    'seeder-token': ('Seeder announce credential', 'review', 'Maintenance freeze and tracker serving proof', 'admin-guide/rotations/#rotate-the-seeder-announce-credential'),
    'metrics-token': ('Metrics scrape credential', 'review', 'Console replacement, scraper migration and verified retirement', 'admin-guide/console-credentials/#replace-the-metrics-scraping-token'),
    'collector-headers': ('Outbound telemetry credentials', 'review', 'Console replacement, collector approval and delivery proof', 'admin-guide/console-credentials/#replace-outbound-collector-authentication'),
}
ACTIVE = {'running', 'approval-required', 'verification-required', 'review-required', 'intervention-required'}
STATES = ACTIVE | {'completed', 'reviewed', 'missed', 'cancelled'}


class MaintenanceError(ValueError):
    pass


def _integer(value, minimum=0, maximum=2**53 - 1):
    return type(value) is int and minimum <= value <= maximum


def _identifier(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError()
    except ValueError:
        raise MaintenanceError('Use a canonical operation ID') from None
    return value


def _cli(name):
    loader = importlib.machinery.SourceFileLoader('_maintenance_' + name, str(Path(__file__).with_name(name)))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    return module


def _fingerprint(value):
    return hashlib.sha256(value).hexdigest()


class Maintenance:
    def __init__(self, directory=None, *, now=None, adapter=None):
        self.directory = Path(directory or os.environ.get('IRIS_STATE', '/srv/state')) / 'key-maintenance'
        self.path = self.directory / 'state.json'
        self.now = now or time.time
        self.adapter = adapter or self._perform

    @contextmanager
    def locked(self):
        self.directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        if self.directory.is_symlink():
            raise MaintenanceError('Unsafe maintenance directory')
        fd = os.open(self.directory / 'state.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise MaintenanceError('Unsafe maintenance lock')
            # API and periodic worker must not pile up behind a slow signer.
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise MaintenanceError('Key maintenance is busy; refresh shortly') from None
            yield
        finally:
            os.close(fd)

    def load(self):
        if not keys._path_exists(self.path, 'maintenance state unavailable'):
            return {'schema': 1, 'revision': 0, 'policies': [], 'jobs': [], 'observed_at': None}
        data = keys._strict_json_loads(keys._read_regular(self.path, 1024 * 1024,
            unavailable='maintenance state unavailable', too_large='maintenance state too large'), 'maintenance state')
        if (not isinstance(data, dict) or set(data) != {'schema', 'revision', 'policies', 'jobs', 'observed_at'}
                or type(data['schema']) is not int or data['schema'] != 1 or not _integer(data['revision'])
                or not isinstance(data['policies'], list) or len(data['policies']) > 32
                or not isinstance(data['jobs'], list) or len(data['jobs']) > 256
                or data['observed_at'] is not None and not _integer(data['observed_at'])):
            raise MaintenanceError('Invalid maintenance state; do not reset it')
        for policy in data['policies']:
            self.validate_policy(policy)
        if len({p['id'] for p in data['policies']}) != len(data['policies']):
            raise MaintenanceError('Duplicate maintenance policies')
        if len({(p['family'], p['target']) for p in data['policies']}) != len(data['policies']):
            raise MaintenanceError('Duplicate maintenance targets')
        for job in data['jobs']:
            if (not isinstance(job, dict) or set(job) != {'id', 'policy_id', 'family', 'target', 'state', 'due_at', 'updated_at', 'detail', 'before', 'after'}
                    or not isinstance(job['family'], str) or job['family'] not in FAMILIES
                    or not isinstance(job['state'], str) or job['state'] not in STATES
                    or not _integer(job['due_at']) or not _integer(job['updated_at'])
                    or not isinstance(job['detail'], str) or len(job['detail']) > 300):
                raise MaintenanceError('Invalid maintenance operation')
            _identifier(job['id'])
            _identifier(job['policy_id'])
            if not any(p['id'] == job['policy_id'] for p in data['policies']):
                raise MaintenanceError('Maintenance operation has no policy')
            self.validate_policy(dict(id=job['policy_id'], family=job['family'], target=job['target'],
                enabled=False, next_at=0, interval_days=14, window_minutes=30))
            for name in ('before', 'after'):
                if job[name] is not None and (not isinstance(job[name], str) or not keys._SHA256.fullmatch(job[name])):
                    raise MaintenanceError('Invalid public key maintenance identity')
        if len({j['id'] for j in data['jobs']}) != len(data['jobs']):
            raise MaintenanceError('Duplicate maintenance operations')
        return data

    def save(self, data):
        keys._atomic_write_json(self.path, data)

    def validate_policy(self, policy):
        if (not isinstance(policy, dict) or set(policy) != {'id', 'family', 'target', 'enabled', 'next_at', 'interval_days', 'window_minutes'}
                or not isinstance(policy['family'], str) or policy['family'] not in FAMILIES
                or type(policy['enabled']) is not bool or not _integer(policy['next_at'])
                or not _integer(policy['interval_days'], 1, 365)
                or not _integer(policy['window_minutes'], 5, 1440)):
            raise MaintenanceError('Invalid key maintenance policy')
        _identifier(policy['id'])
        if policy['family'] == 'device-instruction':
            if not isinstance(policy['target'], str) or instructions.DEVICE_ID.fullmatch(policy['target']) is None:
                raise MaintenanceError('Choose one enrolled device ID')
            try:
                secrets_store.validate_device_id(policy['target'])
            except (ValueError, TypeError):
                raise MaintenanceError('Choose one enrolled device') from None
            if not 8 <= policy['interval_days'] <= 21:
                raise MaintenanceError('Device key rotation interval must be 8–21 days to respect overlap and expiry')
        elif policy['target'] != 'deployment':
            raise MaintenanceError('This family targets the deployment')

    def status(self):
        with self.locked():
            data = self.load()
        return self._view(data)

    def _view(self, data):
        observed = data['observed_at']
        worker = ('not-observed' if observed is None else 'clock-error' if int(self.now()) < observed
                  else 'stale' if int(self.now()) - observed > 90 else 'observed')
        return {**data, 'worker': worker, 'families': [dict(id=k, label=v[0], action=v[1], requirement=v[2], guide=v[3])
                for k, v in FAMILIES.items()], 'peer_leaf_renewal': 'Device-managed; one-day certificates renew six hours before expiry.'}

    def update(self, payload):
        if (not isinstance(payload, dict) or set(payload) != {'action', 'revision', 'policy'}
                or payload['action'] != 'save-policy' or not _integer(payload['revision'])):
            raise MaintenanceError('Expected a policy and current revision')
        policy = payload['policy']
        self.validate_policy(policy)
        with self.locked():
            data = self.load()
            if data['revision'] != payload['revision']:
                raise MaintenanceError('Maintenance policies changed; refresh before saving')
            others = [p for p in data['policies'] if p['id'] != policy['id']]
            if len(others) >= 32 or any(p['family'] == policy['family'] and p['target'] == policy['target'] for p in others):
                raise MaintenanceError('One policy per family and target; maximum 32')
            if policy['enabled'] and policy['next_at'] < int(self.now()):
                raise MaintenanceError('Choose a future UTC start time')
            existing = next((p for p in data['policies'] if p['id'] == policy['id']), None)
            disabling = existing is not None and policy == dict(existing, enabled=False)
            if not disabling and any(j['policy_id'] == policy['id'] and j['state'] in ACTIVE for j in data['jobs']):
                raise MaintenanceError('Resolve this policy’s active operation before changing it')
            data['policies'] = others + [dict(policy)]
            data['revision'] += 1
            self.save(data)
        return self.status()

    def _perform(self, job, checkpoint):
        family = job['family']
        if FAMILIES[family][1] == 'review':
            return 'review-required', 'Operator trust/custody procedure required; no credential was changed.'
        if family == 'online-signer':
            instruction_rotation.prepare(job['id'])
            return 'approval-required', 'Replacement prepared. Complete the offline signer approval and retirement workflow.'
        if family == 'management-token':
            module = _cli('iris-management-token')
            with module.locked():
                current_path, previous_path = module._paths()
                current, previous = tier_auth.load_pair(current_path, previous_path)
                job['before'] = _fingerprint(current)
                checkpoint()
                if previous is not None:
                    raise MaintenanceError('Finish the existing management credential overlap first')
                module._rotate_locked()
                current, previous = tier_auth.load_pair(current_path, previous_path)
                if previous is None or _fingerprint(previous) != job['before']:
                    raise MaintenanceError('Management credential authority changed')
                job['after'] = _fingerprint(current)
            return 'verification-required', 'New management credential active. Update and verify every Console before retiring overlap.'
        if family == 'device-instruction':
            device = job['target']
            cli = _cli('iris-instr-key')
            callback = cli.resolve_default_restamp()
            secret_path = os.environ.get('IRIS_SECRETS', '/run/iris/secrets.json')
            recipients = os.environ.get('IRIS_AGE_RECIPIENTS', '')
            encrypted = os.environ.get('IRIS_SECRETS_ENC', '/etc/iris/secrets.json.age')
            if not recipients or not Path(encrypted).is_file():
                raise MaintenanceError('Durable encrypted device custody is required')
            with instruction_stamper.rotation_context(device):
                with secrets_store.store_lock(secret_path):
                    store = secrets_store.load(secret_path)
                    records = store.get('devices', {}).get(device, {})
                    current = secrets_store.validate_instruction_key_record(records.get('instr_key'))
                    if current['revoked'] or any(isinstance(v, dict) and v.get('revoked') for v in records.values()):
                        raise MaintenanceError('Revoked devices cannot be rotated')
                    if job['after'] is not None and current['key_id'] == job['after']:
                        key_id = job['after']  # Durable commit happened; restamp only.
                    else:
                        if job['before'] is not None and current['key_id'] != job['before']:
                            raise MaintenanceError('Device key changed outside this operation')
                        job['before'] = current['key_id']
                        key_id = secrets_store.rotate_instruction_key(store, device, int(self.now()))
                        job['after'] = key_id
                        checkpoint()  # Public intent precedes encrypted persistence.
                        secretfs.persist_store(store, secret_path, recipients_csv=recipients, enc_path=encrypted)
                cli.handoff_restamp(callback, device, key_id)
            return 'completed', 'Device key rotated with seven-day overlap and fresh instructions; verify device acceptance.'
        raise MaintenanceError('Unsupported rotation family')

    def _execute(self, data, job):
        job.update(state='running', updated_at=int(self.now()), detail='Operation admitted; completion not yet established.')
        self.save(data)
        try:
            state, detail = self.adapter(job, lambda: self.save(data))
            if state not in STATES:
                raise MaintenanceError('Invalid operation outcome')
            job.update(state=state, detail=detail)
        except Exception:
            # Never persist exceptions from subprocesses, files or credentials.
            job.update(state='intervention-required', detail='Operation incomplete or outcome uncertain. Review custody before an explicit retry.')
        job['updated_at'] = int(self.now())
        self.save(data)

    def tick(self):
        with self.locked():
            data, now = self.load(), int(self.now())
            if data['observed_at'] is not None and now < data['observed_at']:
                raise MaintenanceError('Clock moved backwards; no maintenance admitted')
            for job in data['jobs']:
                if job['state'] == 'running':
                    job.update(state='intervention-required', detail='Interrupted operation. Review custody before retrying.', updated_at=now)
                if job['state'] == 'approval-required':
                    state = instruction_rotation.status()
                    if state['request_id'] == job['id'] and state['state'] == 'completed':
                        job.update(state='completed', detail='Signer rotation and root-approved retirement completed.', updated_at=now)
                    elif state['request_id'] == job['id'] and state['state'] == 'cancelled':
                        job.update(state='cancelled', detail='Pending signer replacement cancelled by the operator.', updated_at=now)
                    elif state['request_id'] != job['id']:
                        job.update(state='intervention-required', detail='Signer custody changed outside this operation; review the rotation journal.', updated_at=now)
            data['observed_at'] = now
            self.save(data)
            # A trust transition must finish before admitting a different one.
            if any(job['state'] in ACTIVE and FAMILIES[job['family']][1] != 'review' for job in data['jobs']):
                return
            pending = {j['policy_id'] for j in data['jobs'] if j['state'] in ACTIVE}
            due = sorted((p for p in data['policies'] if p['enabled'] and p['next_at'] <= now and p['id'] not in pending), key=lambda p: (p['next_at'], p['id']))
            if not due:
                return
            if len(data['jobs']) >= 256:
                finished = next((j for j in data['jobs'] if j['state'] not in ACTIVE), None)
                if finished is None:
                    raise MaintenanceError('Maintenance history capacity reached; no new keys generated')
                data['jobs'].remove(finished)
            policy = due[0]
            slot = policy['next_at']
            # Skip elapsed slots in one jump; never replay a backlog of changes.
            interval = policy['interval_days'] * DAY
            policy['next_at'] = slot + ((now - slot) // interval + 1) * interval
            data['revision'] += 1
            job = dict(id=str(uuid.uuid5(uuid.UUID(policy['id']), str(slot))), policy_id=policy['id'],
                family=policy['family'], target=policy['target'], due_at=slot, updated_at=now,
                state='missed', detail='Maintenance window elapsed; no key changed.', before=None, after=None)
            data['jobs'].append(job)
            self.save(data)
            if now < slot + policy['window_minutes'] * 60:
                self._execute(data, job)

    def act(self, payload, *, presented=None):
        if (not isinstance(payload, dict) or set(payload) != {'action', 'job_id', 'confirm'}
                or payload['action'] not in ('retry', 'reviewed', 'retire-management', 'reconcile-management') or payload['confirm'] is not True):
            raise MaintenanceError('Confirm one bounded maintenance operation')
        _identifier(payload['job_id'])
        with self.locked():
            data = self.load()
            job = next((j for j in data['jobs'] if j['id'] == payload['job_id']), None)
            if job is None:
                raise MaintenanceError('Unknown maintenance operation')
            action = payload['action']
            if action == 'reviewed' and job['state'] in ('review-required', 'reviewed'):
                job.update(state='reviewed', detail='Operator acknowledged review; this is not evidence of key rotation.')
            elif action == 'retry' and job['state'] == 'intervention-required' and job['family'] in ('online-signer', 'device-instruction'):
                self._execute(data, job)
            elif action == 'reconcile-management' and job['family'] == 'management-token' and job['state'] == 'intervention-required':
                # The adapter must durably checkpoint the old identity before
                # touching either credential. No identity means no mutation
                # was admitted, even if a read-only mount prevents locking.
                if job['before'] is None and job['after'] is None:
                    job.update(state='cancelled', detail='No credential change was admitted; operation cancelled.', updated_at=int(self.now()))
                    self.save(data)
                    return self._view(data)
                module = _cli('iris-management-token')
                with module.locked():
                    current, previous = tier_auth.load_pair(*module._paths())
                    if (job['before'] is not None and previous is not None
                            and _fingerprint(previous) == job['before'] and _fingerprint(current) != job['before']):
                        job.update(after=_fingerprint(current), state='verification-required',
                            detail='Replacement and overlap recovered. Verify every Console before retiring overlap.')
                    elif job['before'] is not None and _fingerprint(current) == job['before']:
                        job.update(state='cancelled', detail='Original credential still active; interrupted rotation cancelled.')
                    else:
                        raise MaintenanceError('Credential files do not prove this operation; restore custody before reconciliation')
            elif action == 'retire-management' and job['family'] == 'management-token' and job['state'] in ('verification-required', 'completed'):
                module = _cli('iris-management-token')
                with module.locked():
                    current_path, previous_path = module._paths()
                    current, previous = tier_auth.load_pair(current_path, previous_path)
                    if (_fingerprint(current) != job['after'] or not isinstance(presented, bytes)
                            or not hmac.compare_digest(current, presented)
                            or previous is not None and _fingerprint(previous) != job['before']):
                        raise MaintenanceError('Use the replacement credential and verify all Console copies before retirement')
                    module._retire_previous_locked()
                job.update(state='completed', detail='Previous management credential retired after current-credential proof and operator confirmation.')
            else:
                raise MaintenanceError('Action is unavailable for this operation state')
            job['updated_at'] = int(self.now())
            self.save(data)
        return self.status()

    def run(self, stop):
        while not stop.is_set():
            try:
                self.tick()
            except Exception:
                # Status/read APIs surface the durable state; never log secrets.
                pass
            stop.wait(30)
