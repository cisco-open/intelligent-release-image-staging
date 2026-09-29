# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Explicit same-deployment restore with current credential and replay authority.

An old backup cannot authorize a lost-primary security rollback. This contract
requires the existing deployment's owned storage, current credentials, immutable
runtime and producer history. It restores backed-up content while carrying the
fenced producer's current replay floors forward. Changed credentials or missing
producer authority refuse admission; no epoch or account is manufactured.
"""

import hashlib
import base64
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import time
import uuid

from . import backup, backup_archive, restore_storage as storage, restore_topology
from .credential_maintenance import _consumer_proof, _memory, _pin_runtime, _stop
from .state import InstallError, Journal, atomic_write, regular_bytes

PHASES = {'verified', 'stopping', 'stopped', 'staged', 'publishing', 'published',
          'restarting', 'restored', 'refused', 'recovery-required'}


def identifier(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise InstallError('Provide a canonical restore operation or backup identifier') from None
    return value


def signer_path(state_dir):
    return Path(state_dir) / 'restore-custody' / 'signer.pub'


def guard(state_dir, *, operation_id=None, instance_id=None, recovery_record=None):
    """Other maintenance entry points must respect an interrupted restore."""
    base = Path(state_dir)
    path, directory = base / 'restore-operation.json', base / 'restore-operations'
    try:
        operations = list(directory.iterdir()) if directory.exists() else []
        missing = not path.exists() and not path.is_symlink()
        if missing and not operations:
            return
        if missing:
            if recovery_record is None:
                raise ValueError()
            record = {key: recovery_record[key] for key in ('operation_id', 'instance_id', 'phase')}
        else:
            record = json.loads(regular_bytes(path))
        if not isinstance(record, dict) or set(record) != {'operation_id', 'instance_id', 'phase'}:
            raise ValueError()
        if record['phase'] not in PHASES:
            raise ValueError()
        identifier(record['operation_id'])
        if instance_id is not None and record['instance_id'] != instance_id:
            raise ValueError()
        seen, recovery_seen = False, False
        for operation in operations:
            identifier(operation.name)
            if operation.resolve() != operation or not operation.is_dir():
                raise ValueError()
            saved = json.loads(regular_bytes(operation / 'record.json', backup_archive.MAX_MANIFEST))
            if (not isinstance(saved, dict) or saved.get('operation_id') != operation.name
                    or saved.get('instance_id') != record['instance_id']
                    or saved.get('phase') not in PHASES):
                raise ValueError()
            if operation.name == record['operation_id']:
                seen = True
            if recovery_record is not None and operation.name == operation_id:
                if saved != recovery_record or saved['instance_id'] != instance_id:
                    raise ValueError()
                recovery_seen = True
            if saved.get('phase') not in ('restored', 'refused') and operation.name != operation_id:
                raise InstallError('Recover the interrupted deployment restore before other maintenance')
        if not seen:
            raise ValueError()
        if record['phase'] not in ('restored', 'refused') and record['operation_id'] != operation_id:
            raise InstallError('Recover the interrupted deployment restore before other maintenance')
        if recovery_record is not None:
            if not recovery_seen:
                raise ValueError()
            # Only the explicit same-ID backend, holding Journal.locked(),
            # can repair the record->pointer crash window. Validate every
            # saved operation first; never replace corrupt/mismatched custody.
            atomic_write(path, json.dumps({key: recovery_record[key] for key in
                ('operation_id', 'instance_id', 'phase')}, sort_keys=True).encode())
    except (OSError, ValueError, TypeError, KeyError):
        raise InstallError('Restore authority is unreadable; preserve state and recover the approved operation') from None


def assert_no_pending_restore(journal):
    guard(journal.directory, instance_id=journal.document['id'])


def custody(state_dir, identity):
    """Trust is explicitly provisioned outside the backup being restored."""
    signer = signer_path(state_dir)
    try:
        backup_archive.private_directory(signer.parent)
        for path in (signer, Path(identity)):
            info = path.lstat()
            if (path.resolve() != path or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid() or info.st_nlink != 1
                    or info.st_mode & 0o022):
                raise InstallError('Unsafe independently provisioned restore custody')
        if Path(identity).stat().st_mode & 0o077:
            raise InstallError('Recovery identity must be private')
    except OSError:
        raise InstallError('Provision the independent recovery identity and trusted backup signer on this host') from None
    return signer


def _records(directory, component):
    inventory = json.loads(regular_bytes(Path(directory) / 'RESTORE-INVENTORY.json', backup_archive.MAX_MANIFEST))
    prefix = component + '/'
    records = []
    for item in inventory['files']:
        if item['name'] == component or item['name'].startswith(prefix):
            record = dict(item)
            record['name'] = '' if item['name'] == component else item['name'][len(prefix):]
            records.append(record)
    if not records:
        raise InstallError('Required restore component is missing')
    return records


def _content_records(records):
    return [{k: v for k, v in item.items() if k not in ('uid', 'gid', 'mode')}
            for item in records]


def _same_tree(left, right):
    return _content_records(storage.inventory(left)) == _content_records(storage.inventory(right))


def _management_generation(install, sources, archived):
    """Recognize only Compose's bootstrap certificate renewal, never a key change."""
    token, ca = 'volume-iris-tier-auth', 'volume-iris-management-ca'
    if token in sources and not _same_tree(sources[token], archived / token):
        raise InstallError('Management credential generation changed since this backup')
    if ca not in sources or _same_tree(sources[ca], archived / ca):
        return False
    config = sources['volume-iris-config'] / 'tls'
    deployment = json.loads(regular_bytes(sources['deployment']))
    env = deployment.get('services', {}).get('iris', {}).get('environment', {})
    if (install.config['target'] not in ('docker', 'docker-split')
            or env.get('IRIS_MANAGEMENT_API_GENERATE_CERT') != '1'
            or any((config / name).exists() or (config / name).is_symlink()
                   for name in ('management-key.pem.age', 'management-crt.pem'))):
        raise InstallError('Management credential generation changed since this backup')
    certificates = [sources[ca] / 'ca.pem', archived / ca / 'ca.pem']
    for directory in (sources[ca], archived / ca):
        if {row['name'] for row in storage.inventory(directory)} != {'', 'ca.pem'}:
            raise InstallError('Unexpected generated management trust files')
    def public(path):
        return install.command(['openssl', 'x509', '-in', path, '-noout', '-pubkey'], capture=True)
    expected = public(config / 'crt.pem')
    properties = []
    for path in certificates:
        value = regular_bytes(path, 65536)
        if (not re.fullmatch(rb'\s*-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*', value)
                or public(path) != expected):
            raise InstallError('Generated management certificate key changed since this backup')
        # Verify self-signature and validity, and compare EVERY extension and
        # identity property. Only generated serial, validity and signature
        # bytes may differ; the durable device key was checked independently.
        install.command(['openssl', 'verify', '-check_ss_sig', '-CAfile', path, path], capture=True)
        properties.append(install.command(['openssl', 'x509', '-in', path, '-noout', '-text',
            '-certopt', 'no_header,no_version,no_serial,no_validity,no_sigdump,no_aux'], capture=True))
    if properties[0] != properties[1]:
        raise InstallError('Generated management certificate trust properties changed since this backup')
    return True


def _console_generation(current, prior, sources, archived, generated_ca):
    if current == prior:
        return
    if generated_ca and isinstance(current, dict) and isinstance(prior, dict):
        try:
            ca = 'volume-iris-management-ca'
            if (base64.b64decode(current['ca.pem'], validate=True) == regular_bytes(sources[ca] / 'ca.pem', 65536)
                    and base64.b64decode(prior['ca.pem'], validate=True) == regular_bytes(archived / ca / 'ca.pem', 65536)
                    and {k: v for k, v in current.items() if k != 'ca.pem'} ==
                        {k: v for k, v in prior.items() if k != 'ca.pem'}):
                return
        except (ValueError, TypeError, KeyError):
            pass
    raise InstallError('Console credentials changed since this backup')


def _kubernetes_resources(path):
    resources = []
    for obj in json.loads(regular_bytes(path, 8 * 1024 * 1024)):
        if obj['kind'] == 'NetworkPolicy' and obj['metadata']['name'] == 'iris-maintenance-isolation':
            continue
        if obj['kind'] == 'Deployment':
            # Clean-stop journals deliberately persist replicas=0. Recovery
            # proves stopped pods independently and restores the configured
            # replica counts only after all storage publication is complete.
            obj['spec'].pop('replicas', None)
        resources.append(obj)
    return resources


def state_authority(current, archived):
    """Keep policy, ownership and external trust in the approved generation.

    Execution and disclosure records are monotonic authority, while descriptive
    inventory, assignments, job history and content remain backup-authoritative.
    """
    unchanged = ('peer-policy', 'deployment_records', 'ca-trust-settings',
                 'audit-export-', 'telemetry-destination', 'instance-id', 'schedules.')
    preserved = ('peer-handouts', 'schedule-progress', 'schedule-retired',
                 'schedule-occurrences', 'schedule-receipts', 'report_ledger',
                 'report-attribution', 'transfer-attestations')
    left = {path.name for path in current.iterdir()}
    right = {path.name for path in archived.iterdir()}
    for name in sorted(left | right):
        if name.startswith(unchanged):
            if name not in left or name not in right or not _same_tree(current / name, archived / name):
                raise InstallError('Policy, device ownership or external trust changed since this backup')
        elif name.startswith(preserved):
            if name not in left:
                raise InstallError('Current execution or disclosure authority is missing')
            destination = archived / name
            if destination.exists():
                if destination.is_dir():
                    shutil.rmtree(destination)
                else:
                    destination.unlink()
            if (current / name).is_dir():
                shutil.copytree(current / name, destination)
            else:
                shutil.copy2(current / name, destination)
            storage.apply_metadata(destination, storage.inventory(current / name))
    # Inventory roles and principal registration are part of policy authority.
    # Ordinary addressing/model metadata may be restored by operator choice.
    def fleet(root):
        directory = root / 'fleet.d'
        paths = sorted(directory.glob('*.json')) if directory.is_dir() else [root / 'fleet.json']
        result = {}
        for path in paths:
            if not path.exists():
                continue
            rows = json.loads(regular_bytes(path, 16 * 1024 * 1024))
            rows = rows.get('devices', rows)
            if isinstance(rows, list):
                rows = {row['device_id']: row for row in rows}
            for device, row in rows.items():
                result[device] = {key: row.get(key) for key in (
                    'role', 'registration_id', 'registered_at', 'credential_profile_id')}
        return result
    if fleet(current) != fleet(archived):
        raise InstallError('Inventory principal or role authority changed since this backup')
    def images(root):
        path = root / 'catalog.json'
        if not path.exists():
            return {}
        document = json.loads(regular_bytes(path, 16 * 1024 * 1024))
        return {name: {key: record.get(key) for key in (
            'quarantined', 'hash_verification', 'cisco_signature_verified', 'sha256', 'sha512')}
                for name, record in document.get('images', {}).items()}
    if images(current) != images(archived):
        raise InstallError('Image quarantine or content authority changed since this backup')


def _config_generation(install, current, archived, identity):
    """Compare all credential/configuration contents, including unknown files.

    Ciphertext randomness must not make identical credentials look different.
    A new field/file is security significant by default, never an allowlist gap.
    """
    left, right = storage.inventory(current), storage.inventory(archived)
    index = {row['name']: row for row in right}
    if {row['name'] for row in left} != set(index):
        raise InstallError('Backup belongs to a different credential generation')
    for row in left:
        other = index[row['name']]
        if row['type'] != other['type']:
            raise InstallError('Backup credential layout changed')
        if row['type'] == 'directory' or row['sha256'] == other['sha256']:
            continue
        if not row['name'].endswith('.age'):
            raise InstallError('Backup belongs to a different credential generation')
        if max(row['size'], other['size']) > 32 * 1024 * 1024:
            raise InstallError('Credential exceeds restore validation bounds')
        actual = install.command(['age', '-d', '-i', install.base / 'age.txt',
                                  current / row['name']], capture=True)
        prior = install.command(['age', '-d', '-i', identity,
                                 archived / row['name']], capture=True)
        if actual != prior:
            raise InstallError('Backup would roll credentials or revocations backward')


def _history(root, *, allow_empty=False):
    directory = root / 'instructions' / 'serial-history.d'
    if directory.is_dir():
        paths = sorted(directory.glob('*.json'))
    else:
        paths = [root / 'instructions' / 'serial-history.json']
        if allow_empty and not paths[0].exists():
            return {}
    result = {}
    for path in paths:
        document = json.loads(regular_bytes(path, 16 * 1024 * 1024))
        if not isinstance(document, dict):
            raise InstallError('Current producer history is invalid')
        for device, row in document.items():
            if (device in result or not isinstance(device, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', device)
                    or not isinstance(row, dict) or set(row) != {'v', 'epoch', 'high_water', 'reservation'}
                    or type(row.get('v')) is not int or row['v'] != 1
                    or any(type(row.get(key)) is not int or not 0 <= row[key] < 2 ** 63
                           for key in ('epoch', 'high_water'))):
                raise InstallError('Current producer history is invalid')
            reservation = row.get('reservation')
            if reservation is not None and (not isinstance(reservation, dict)
                    or reservation.get('instr_serial') != row['high_water']
                    or not re.fullmatch('[0-9a-f]{64}', str(reservation.get('desired_sha256', '')))):
                raise InstallError('Current producer reservation is invalid')
            result[device] = row
    return result


def replay_overlay(current, archived):
    """Carry a proven current producer forward; never reset a missing floor."""
    for name in ('instructions-epoch.json', 'instructions/activation.json'):
        live = json.loads(regular_bytes(current / name))
        prior = json.loads(regular_bytes(archived / name))
        if live != prior:
            raise InstallError('Producer epoch changed or is unavailable; restore refused')
        schema = 'iris-instructions-epoch/v1' if name == 'instructions-epoch.json' else 'iris-instruction-producer/v1'
        if (not isinstance(live, dict) or live.get('schema') != schema
                or type(live.get('epoch')) is not int or not 0 <= live['epoch'] < 2 ** 63):
            raise InstallError('Current producer authority is invalid')
    admissions = json.loads(regular_bytes(current / 'instructions/admitted-devices.json', 8 * 1024 * 1024))
    prior_admissions = json.loads(regular_bytes(archived / 'instructions/admitted-devices.json', 8 * 1024 * 1024))
    if admissions != prior_admissions:
        raise InstallError('Producer admission authority changed since this backup')
    empty = isinstance(admissions, dict) and admissions.get('devices') == {}
    old, now = _history(archived, allow_empty=empty), _history(current, allow_empty=empty)
    for device, row in old.items():
        live = now.get(device)
        if (live is None or live['epoch'] != row['epoch']
                or live['high_water'] < row['high_water']):
            raise InstallError('Current producer replay floor does not dominate the backup')
    if (not isinstance(admissions, dict) or admissions.get('schema') != 'iris-instruction-admissions/v1'
            or not isinstance(admissions.get('devices'), dict)
            or any(device not in now for device in admissions['devices'])):
        raise InstallError('Current producer admission or replay authority is missing')
    for root in (current, archived):
        marker = root / 'instructions/keylist-state.json'
        if marker.exists():
            record = json.loads(regular_bytes(marker))
            payload = regular_bytes(root / 'instructions/keylist.current', 128 * 1024)
            if (record.get('schema') != 'iris-instruction-keylist-state/v1'
                    or type(record.get('keylist_seq')) is not int or record['keylist_seq'] < 1
                    or record.get('artifact_sha256') != hashlib.sha256(payload).hexdigest()):
                raise InstallError('Instruction revocation authority is invalid')
    old_keylist = archived / 'instructions/keylist-state.json'
    if old_keylist.exists():
        latest = json.loads(regular_bytes(current / 'instructions/keylist-state.json'))
        prior = json.loads(regular_bytes(old_keylist))
        if latest['keylist_seq'] < prior['keylist_seq'] or (latest['keylist_seq'] == prior['keylist_seq']
                and latest['artifact_sha256'] != prior['artifact_sha256']):
            raise InstallError('Current instruction revocation floor would roll backward')
    # The current keylist, admissions, outstanding serial reservation and
    # immutable signed roles form one producer generation and move together.
    for name in ('instructions', 'instructions-epoch.json'):
        destination = archived / name
        if destination.is_dir():
            shutil.rmtree(destination)
            shutil.copytree(current / name, destination)
        else:
            shutil.copy2(current / name, destination)
    # copytree/copy2 do not preserve ownership. Apply the live custody exactly.
    for name in ('instructions', 'instructions-epoch.json'):
        storage.apply_metadata(archived / name, storage.inventory(current / name))
    return {'producer_epoch': 'unchanged', 'replay_floor': 'current-fenced-primary',
            'current_history_rows': len(now)}


def _producer_proof(install):
    """Use the installed runtime's schemas and cryptographic trust verifier."""
    from .trust_maintenance import _one_shot
    code = '''
import instruction_keys as k, instruction_stamper as s, json, os, tempfile
import secrets_store, secretfs, peer_handouts, peer_policy, schedules
p=k.InstructionPaths.from_env(); q=s.StamperPaths.from_env()
status=k.refresh_custody_status(p)
if not status['enabled'] or status['signing_refused'] or status['state'] in ('error','invalid'):
 raise RuntimeError('Current signing authority is not valid')
activation=s._validated_activation_epoch(q); admissions=s._read_admissions(q)
rows=s._history(q).snapshot()
if admissions['epoch']!=activation['epoch']: raise RuntimeError('admission epoch')
for device in admissions['devices']:
 if device not in rows or rows[device]['epoch']!=activation['epoch']: raise RuntimeError('missing producer floor')
peer_handouts.initialize(q.handouts,create=False)
policy=peer_policy._read_valid(q.policy_authoritative)
if policy is None: raise RuntimeError('current policy authority unavailable')
schedule=schedules.ScheduleStore(q.state_dir)
schedule._rows.snapshot(); schedule._progress.snapshot(); schedule._retired.snapshot()
occurrences=schedules.OccurrenceStore(q.state_dir)._rows.snapshot()
outcomes=schedules.ReceiptStore(q.state_dir)
for identifier in occurrences: outcomes._rows(identifier).snapshot()
with tempfile.TemporaryDirectory(dir=p.run_dir) as directory:
 path=os.path.join(directory,'restore-secrets.json')
 secretfs.decrypt_to(os.path.join(p.config_dir,'secrets.json.age'),path,os.environ['IRIS_AGE_KEY_FILE'])
 secrets=secrets_store.load(path,require_existing=True)
 if 'admin' in secrets and (not isinstance(secrets['admin'],dict) or not secrets['admin'].get('username')):
  raise RuntimeError('existing owner account invalid')
print(json.dumps({'signing_authority':'verified','revocations':'current-verified-keylist'}))
'''
    result = json.loads(_one_shot(install, code))
    if result != {'signing_authority': 'verified', 'revocations': 'current-verified-keylist'}:
        raise InstallError('Current signing and owner authority could not be verified')
    return result


def _fence(install, containers, recovery):
    _stop(install, containers, recovering_clean_operation=recovery)
    hook = getattr(install, 'assert_writers_stopped', None)
    if hook:
        hook()
    # Re-resolve resource ownership and every foreign writable Docker mount.
    # Kubernetes assert_writers_stopped checks PVC consumers and object UIDs.
    if install.config['target'] != 'kubernetes':
        backup.capture_plan(install)


def _start(install):
    before = getattr(install, 'before_server_start', None)
    if before:
        before()
    install.compose('up', '-d', '--no-build', '--no-deps', '--force-recreate',
                    '--wait', '--wait-timeout', '180', 'iris')
    before = getattr(install, 'before_console_start', None)
    if before:
        before()
    install.compose('up', '-d', '--no-build', '--no-deps', '--force-recreate',
                    '--wait', '--wait-timeout', '180', 'console')
    return _consumer_proof(install)


class Transaction:
    def __init__(self, state_dir, backup_dir, recovery_dir, *, operation_id, backup_id,
                 recovery_identity):
        if os.geteuid() != 0:
            raise InstallError('Restore requires the managed host worker')
        self.base = backup_archive.private_directory(state_dir)
        self.backups = backup_archive.private_directory(backup_dir)
        self.recoveries = backup_archive.private_directory(recovery_dir)
        if self.backups == self.recoveries:
            raise InstallError('Restore requires separate data and identity custody')
        self.id, self.backup_id = identifier(operation_id), identifier(backup_id)
        self.identity = Path(recovery_identity).absolute()
        self.signer = custody(self.base, self.identity)
        self.directory = self.base / 'restore-operations' / self.id
        self.record = None

    def save(self, phase):
        self.record['phase'] = phase
        atomic_write(self.directory / 'record.json', json.dumps(self.record, sort_keys=True).encode())
        atomic_write(self.base / 'restore-operation.json', json.dumps({key: self.record[key]
            for key in ('operation_id', 'instance_id', 'phase')}, sort_keys=True).encode())

    def run(self, *, recovery=False, pre_authority_recovery=False, on_authority_started=None):
        with Journal(self.base).locked() as journal:
            if journal.document is None:
                raise InstallError('Restore requires an existing owned deployment')
            install = backup._installation(journal)
            _pin_runtime(install)
            if (recovery and pre_authority_recovery and self.directory.exists()
                    and not (self.directory / 'record.json').exists()):
                backup_archive.private_directory(self.directory)
                # mkdir can precede the first atomic record write. The
                # protected false handoff marker proves no fence ever began.
                # Reuse only a truly empty owned directory, never lost or
                # damaged record contents or partial publication artifacts.
                if any(self.directory.iterdir()):
                    raise InstallError('Preflight restore custody is incomplete; preserve the operation')
                self.directory.rmdir()
                storage.sync(self.directory.parent)
            if self.directory.exists():
                backup_archive.private_directory(self.directory)
                self.record = json.loads(regular_bytes(self.directory / 'record.json', backup_archive.MAX_MANIFEST))
                if (not isinstance(self.record, dict) or self.record.get('schema') != 1
                        or self.record.get('phase') not in PHASES
                        or any(type(self.record.get(key)) is not bool for key in
                               ('mutations_admitted', 'published', 'initial_clean_stop'))
                        or not re.fullmatch(r'[0-9a-f]{64}', str(self.record.get('data_sha256', '')))):
                    raise InstallError('Restore recovery record is invalid; preserve approved operation custody')
                if any(self.record.get(key) != value for key, value in (
                        ('operation_id', self.id), ('backup_id', self.backup_id),
                        ('instance_id', journal.document['id']))):
                    raise InstallError('Restore recovery does not match the approved operation')
                if recovery:
                    guard(self.base, operation_id=self.id, instance_id=journal.document['id'],
                          recovery_record=self.record)
                else:
                    guard(self.base, instance_id=journal.document['id'])
                if self.record['phase'] == 'restored':
                    self.save('restored')
                    return self.record['result']
                if not recovery:
                    raise InstallError('Interrupted restore requires explicit same-ID recovery')
            elif recovery and not pre_authority_recovery:
                raise InstallError('There is no restore operation to recover')
            guard(self.base, operation_id=self.id if self.record is not None else None,
                  instance_id=journal.document['id'])
            install.restore_operation_id = self.id
            sources, volumes, containers = backup.capture_plan(install)
            # Both authenticated sets and topology are checked before downtime.
            data = backup_archive.read(self.backups / self.backup_id, self.identity, self.signer)
            keys = backup_archive.read(self.recoveries / self.backup_id, self.identity, self.signer)
            for report, scope in ((data, 'managed-deployment-files'), (keys, 'identity-recovery')):
                meta = report['metadata']
                if (meta.get('scope') != scope or meta.get('instance_id') != journal.document['id']
                        or meta.get('target') != backup.target_name(install)
                        or meta.get('image_ids') != journal.document['completed']['images']
                        or meta.get('volumes') != volumes):
                    raise InstallError('Backup does not match this deployment, storage and immutable runtime')
            if not data['metadata'].get('backup_set_id') or data['metadata']['backup_set_id'] != keys['metadata'].get('backup_set_id'):
                raise InstallError('Data and identity recovery sets do not match')
            recipient = install.command(['age-keygen', '-y', self.identity], capture=True).strip()
            service = install.command(['age-keygen', '-y', self.base / 'age.txt'], capture=True).strip()
            if recipient == service:
                raise InstallError('Restore requires recovery custody independent of the service identity')
            envelope = backup_archive.authenticate(self.backups / self.backup_id, self.signer)
            if recipient.decode() != envelope['recipient']:
                raise InstallError('Independent recovery identity does not match this backup')
            if not self.record or not self.record.get('published'):
                if shutil.disk_usage(self.base).free < data['bytes'] * 2 + 1024 ** 3:
                    raise InstallError('Insufficient host space for verified extraction and restore candidates')
            if self.record is None:
                self.directory.parent.mkdir(mode=0o700, exist_ok=True)
                backup_archive.private_directory(self.directory.parent)
                self.directory.mkdir(mode=0o700)
                self.record = dict(schema=1, operation_id=self.id, backup_id=self.backup_id,
                    instance_id=journal.document['id'], phase='verified', started_at=int(time.time()),
                    mutations_admitted=False, published=False, initial_clean_stop=False,
                    data_sha256=envelope['payload_sha256'])
                self.save('verified')
            elif self.record['data_sha256'] != envelope['payload_sha256']:
                raise InstallError('Approved restore backup bytes changed')
            if on_authority_started is not None:
                on_authority_started()
            install.credential_transaction = self
            install.credential_recovery = recovery
            self.save('stopping')
            try:
                _fence(install, containers, recovery and self.record['initial_clean_stop'])
                self.record['initial_clean_stop'] = True
                self.save('stopped')
                if not self.record['published']:
                    self._prepare(install, sources)
                    self.record['mutations_admitted'] = True
                    self.save('publishing')
                    for item in self.record['plan']:
                        if item.get('pvc'):
                            restore_topology.publish(install, self.id, item['pvc'], item['before'], item['after'])
                        else:
                            storage.publish(item['target'], item['staged'], item['retained'], item['before'], item['after'])
                    self.record['published'] = True
                    self.save('published')
                # Durable publication precedes ANY restart. Recovery after a
                # failed health/consumer check never reapplies an old snapshot
                # over state written by a newly started producer.
                self.save('restarting')
                proof = _start(install)
                proof.update(self.record['security_proof'])
                proof.update(scope='same-deployment', sessions='invalidated-by-console-restart',
                             device_acceptance='not-qualified')
                self.record['result'] = dict(state='restored', backup_id=self.backup_id, proof=proof)
                self.save('restored')
                cleanup = getattr(install, 'cleanup_snapshot_sources', None)
                if cleanup:
                    cleanup(sources)
                return self.record['result']
            except BaseException:
                if not self.record['mutations_admitted'] and self.record['initial_clean_stop']:
                    # Admission was refused before any live replacement. Resume
                    # the unchanged original deployment and permit a new choice.
                    try:
                        _start(install)
                    except BaseException:
                        pass
                    else:
                        self.save('refused')
                        raise
                # Fail closed even after one service started. Never automatically
                # put the retained preimage back over a possible new writer.
                try:
                    install.verify_resource_ownership()
                    install.compose('stop', '--timeout', '120', 'console', 'iris', timeout=300)
                finally:
                    self.save('recovery-required')
                raise

    def _prepare(self, install, sources):
        if self.record.get('plan'):
            return  # Fully staged, validated candidates survive worker loss.
        target = install.config['target']
        authority = _producer_proof(install)
        if target == 'kubernetes':
            install.capture_backup_extras(sources)
        # Data extraction contains the same at-rest ciphertext as the protected
        # deployment. The service private identity is decrypted only into tmpfs.
        with _memory(install) as memory, tempfile.TemporaryDirectory(prefix='restore-data-', dir=self.directory) as temporary:
            extracted = Path(temporary) / 'data'
            backup_archive.read(self.backups / self.backup_id, self.identity, self.signer, destination=extracted)
            keys = memory / 'identity'
            backup_archive.read(self.recoveries / self.backup_id, self.identity, self.signer, destination=keys)
            if regular_bytes(keys / 'service-identity') != regular_bytes(self.base / 'age.txt'):
                raise InstallError('Service identity changed since this backup; credential rollback refused')
            archived_journal = json.loads(regular_bytes(extracted / 'installation'))
            current = install.journal.document
            for field in ('config', 'source_manifest', 'root_digests'):
                if archived_journal.get(field) != current.get(field):
                    raise InstallError('Deployment or trust inputs changed since this backup')
            for name in ('deployment', 'environment', 'source', 'roots'):
                if not _same_tree(sources[name], extracted / name):
                    raise InstallError('Restore requires the same deployment and source generation')
            _config_generation(install, sources['volume-iris-config'], extracted / 'volume-iris-config', keys / 'service-identity')
            generated_ca = _management_generation(install, sources, extracted)
            if target == 'docker-split':
                for name in ('console-deployment', 'console-build'):
                    if not _same_tree(sources[name], extracted / name):
                        raise InstallError('Console topology changed since this backup')
                payload = install.command(['age', '-d', '-i', self.identity,
                                           extracted / 'remote-console-custody'], capture=True)
                _console_generation(json.loads(install.console_custody_snapshot()), json.loads(payload),
                                    sources, extracted, generated_ca)
            if target == 'kubernetes':
                if not _same_tree(sources['lifecycle-custody'], extracted / 'lifecycle-custody'):
                    raise InstallError('Kubernetes lifecycle trust changed since this backup')
                if _kubernetes_resources(sources['kubernetes-resources']) != _kubernetes_resources(extracted / 'kubernetes-resources'):
                    raise InstallError('Kubernetes topology or Secret authority changed since this backup')
            # Restore original archive custody before adding live producer
            # members, so old metadata cannot overwrite the overlay's modes.
            storage.apply_metadata(extracted / 'volume-iris-state', _records(extracted, 'volume-iris-state'))
            state_authority(sources['volume-iris-state'], extracted / 'volume-iris-state')
            proof = replay_overlay(sources['volume-iris-state'], extracted / 'volume-iris-state')
            proof.update(authority)
            plan = []
            components = [name for name in sources if name.startswith('volume-') or name in ('images', 'artifacts')]
            if generated_ca:
                # This public projection is regenerated from the unchanged
                # durable key at startup; keep its current verified copy.
                components.remove('volume-iris-management-ca')
            for name in components:
                source = extracted / name
                records = _records(extracted, name)
                if name == 'volume-iris-state':
                    # Overlay above may add live producer files absent in backup.
                    records = storage.inventory(source)
                else:
                    storage.apply_metadata(source, records)
                before = storage.fingerprint(storage.inventory(sources[name]))
                after = storage.fingerprint(records)
                if target == 'kubernetes' and name.startswith('volume-'):
                    component = name.removeprefix('volume-iris-')
                    restore_topology.stage(install, self.id, component, source, records)
                    plan.append(dict(pvc=component, before=before, after=after))
                else:
                    live = Path(sources[name])
                    staged = live.with_name('.iris-restore-' + self.id + '-' + name)
                    retained = live.with_name('.iris-retained-' + self.id + '-' + name)
                    needed = sum(row['size'] for row in records)
                    if shutil.disk_usage(live.parent).free < needed + 1024 ** 3:
                        raise InstallError('Insufficient space for restore candidate and retained original')
                    storage.candidate(source, staged, records)
                    plan.append(dict(target=str(live), staged=str(staged), retained=str(retained), before=before, after=after))
            self.record.update(plan=plan, security_proof=proof)
            self.save('staged')


def restore(state_dir, backup_dir, recovery_dir, *, operation_id, backup_id,
            recovery_identity, recovery=False, pre_authority_recovery=False, on_authority_started=None):
    return Transaction(state_dir, backup_dir, recovery_dir, operation_id=operation_id,
                       backup_id=backup_id, recovery_identity=recovery_identity).run(recovery=recovery,
                           pre_authority_recovery=pre_authority_recovery,
                           on_authority_started=on_authority_started)
