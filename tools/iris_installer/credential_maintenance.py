# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Stopped-writer credential maintenance for installer-owned deployments.

The independently decrypted backup is a recovery prerequisite, not an automatic
rollback: a failed operation stays stopped until the same approved operation is
explicitly recovered. Candidates and resumable write plans are encrypted to the
external recovery recipient. Only public evidence crosses the worker boundary.
"""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time
from types import SimpleNamespace
import uuid

from . import backup, backup_archive
from .deploy import DockerInstall, digest
from .state import InstallError, Journal, atomic_write, regular_bytes


KINDS = frozenset(('age-identity', 'age-recovery', 'management-tls', 'seeder-announce'))
MAX_SECRET = 32 * 1024 * 1024


def _json(path, value):
    atomic_write(path, (json.dumps(value, sort_keys=True) + '\n').encode())


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _safe_file(path, *, private=False):
    path = Path(path).absolute()
    if path.resolve() != path:
        raise InstallError('Credential path traverses a symbolic link')
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or (private and (info.st_uid != os.geteuid() or info.st_mode & 0o077))):
        raise InstallError('Unsafe credential file custody')
    return info


def _encrypt(install, value, recipients):
    command = ['age']
    for recipient in recipients:
        if not re.fullmatch(r'age1[0-9a-z]{58}', recipient):
            raise InstallError('Unsupported age recipient')
        command.extend(('-r', recipient))
    return install.command(command, input=value, capture=True, timeout=120)


def _decrypt(install, value, identity):
    return install.command(['age', '-d', '-i', str(identity)], input=value,
                           capture=True, timeout=120)


@contextmanager
def _memory(install):
    """Private transient files only on verified memory-backed storage."""
    root = Path('/dev/shm')
    if (root.resolve() != root or install.command(
            ['stat', '-f', '-c', '%T', root], capture=True).strip() != b'tmpfs'):
        raise InstallError('Verified memory-backed scratch is required')
    with tempfile.TemporaryDirectory(prefix='iris-credential-', dir=root) as name:
        yield Path(name)


def _stop(install, containers, *, recovering_clean_operation=False):
    hook = getattr(install, 'stop_writers', None)
    if hook is not None:
        return hook(containers, recovering_clean_operation=recovering_clean_operation)
    for container in containers:  # Console first, server last.
        record, = json.loads(install.command(
            ['docker', 'container', 'inspect', container['id']], capture=True))
        if record['State']['Running']:
            install.command(['docker', 'stop', '--time', '120', container['id']], timeout=180)
        record, = json.loads(install.command(
            ['docker', 'container', 'inspect', container['id']], capture=True))
        state = record['State']
        if state['Running'] or (not recovering_clean_operation and (
                state.get('OOMKilled') or state.get('ExitCode') not in (0, 143))):
            raise InstallError('Credential maintenance requires cleanly stopped writers')


def _consumer_proof(install):
    """A real authenticated, CA/hostname-verified request FROM the Console."""
    hook = getattr(install, 'lifecycle_consumer_proof', None)
    if hook is not None:
        result = hook()
        if (not isinstance(result, dict) or result.get('management_https') != 'verified'
                or not isinstance(result.get('certificate_sha256'), str)
                or not re.fullmatch('[0-9a-f]{64}', result.get('certificate_sha256', ''))):
            raise InstallError('Management consumer proof was not returned')
        return result
    code = '''import os,sys,ssl,http.client,hashlib,json
sys.path.insert(0,'/opt/iris/server')
import tier_auth
from urllib.parse import urlsplit
u=urlsplit(os.environ['IRIS_MANAGEMENT_API_URL'])
if u.scheme != 'https' or u.username or u.password: raise RuntimeError('origin')
c=http.client.HTTPSConnection(u.hostname,u.port or 443,timeout=15,
 context=ssl.create_default_context(cafile=os.environ['IRIS_MANAGEMENT_API_CA']))
t,_=tier_auth.load_pair(os.environ['IRIS_MANAGEMENT_API_TOKEN_FILE'])
c.connect()
fingerprint=hashlib.sha256(c.sock.getpeercert(binary_form=True)).hexdigest()
c.request('GET','/internal/v1/console-certificate',headers={
 'Authorization':'Bearer '+t.decode(),'X-IRIS-Default-Certificate':'available'})
r=c.getresponse()
if r.status not in (200,204): raise RuntimeError('authentication')
c.close()
print(json.dumps({'management_https':'verified','certificate_sha256':fingerprint}))
'''
    result = json.loads(install.compose('exec', '-T', 'console', 'python3', '-I', '-B',
                                       '-c', code, capture=True, timeout=30))
    if (result.get('management_https') != 'verified'
            or not re.fullmatch('[0-9a-f]{64}', result.get('certificate_sha256', ''))):
        raise InstallError('Management consumer proof was not returned')
    return result


def _pin_runtime(install):
    """Keep runtime commands on the recorded immutable images, never a tag.

    The durable deployment input retains its original tag and ownership pins.
    A private, short-lived Compose projection prevents a concurrent tag change
    between inspection and container creation from selecting different code.
    """
    hook = getattr(install, 'pin_runtime', None)
    if hook is not None:
        return hook()
    images = install.journal.document['completed'].get('images')
    if not isinstance(images, dict) or not images:
        raise InstallError('Recorded deployment images are required for maintenance')
    install.build()  # Existing-image verification only; never bootstrap builds.
    def compose(*args, **kwargs):
        specification = json.loads(regular_bytes(install.compose_file))
        for service in specification['services'].values():
            image = images.get(service.get('image'))
            if not isinstance(image, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
                raise InstallError('Deployment image is outside the recorded immutable set')
            service['image'] = image
            service.pop('build', None)
        with tempfile.TemporaryDirectory(prefix='credential-runtime-', dir=install.base) as directory:
            path = Path(directory) / 'compose.json'
            _json(path, specification)
            return install.command(['docker', 'compose', '-p', install.config['instance'],
                                    '-f', path, *args], **kwargs)
    install.compose = compose


def _installation(journal):
    if journal.document['config'].get('target', 'docker') == 'docker':
        return DockerInstall(journal)
    from .deploy import installation
    return installation(journal)


def _before_console_start(install):
    hook = getattr(install, 'before_console_start', None)
    if hook is not None:
        hook()


class Transaction:
    """Common custody/restart adapter, including approved trust transitions.

    Callbacks take (install, kind, operation_id). Apply runs with ALL normal
    writers stopped. Finish runs with only the server restarted. Recovery must
    be explicit, same-ID and callback-idempotent; never approve a new candidate.
    """

    def __init__(self, state_dir, backup_dir, recovery_dir, *, kind,
                 operation_id, recovery_identity):
        if os.geteuid() != 0:
            raise InstallError('Credential maintenance requires the host worker')
        try:
            if str(uuid.UUID(operation_id)) != operation_id:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise InstallError('Invalid credential operation identifier') from None
        if not re.fullmatch('[a-z][a-z-]{1,40}', kind):
            raise InstallError('Invalid credential family')
        if recovery_identity is None:
            raise InstallError('Provision the independent backup recovery identity first')
        self.base = backup_archive.private_directory(state_dir)
        self.backups = backup_archive.private_directory(backup_dir)
        self.recoveries = backup_archive.private_directory(recovery_dir)
        if self.backups == self.recoveries:
            raise InstallError('Backup and recovery custody must be separate')
        self.identity = Path(recovery_identity).absolute()
        _safe_file(self.identity, private=True)
        self.kind, self.id = kind, operation_id
        self.directory = self.base / 'credential-operations' / operation_id
        self.pointer = self.base / 'credential-operation.json'
        self.record = None

    def save(self, phase):
        self.record['phase'] = phase
        _json(self.directory / 'record.json', self.record)
        _json(self.pointer, self.record)

    def _backup_proof(self, install):
        signer = self.base / 'backup-custody/signer.pub'
        backup_id = self.record.get('backup_id', self.id)
        if not isinstance(backup_id, str) or str(uuid.UUID(backup_id)) != backup_id:
            raise InstallError('Invalid bound credential backup identifier')
        data = backup_archive.read(self.backups / backup_id, self.identity, signer)
        keys = backup_archive.read(self.recoveries / backup_id, self.identity, signer)
        if (data['metadata'].get('backup_set_id') != keys['metadata'].get('backup_set_id')
                or not data['metadata'].get('backup_set_id')
                or data['metadata'].get('instance_id') != install.journal.document['id']
                or keys['metadata'].get('instance_id') != install.journal.document['id']
                or data['metadata'].get('scope') != 'managed-deployment-files'
                or keys['metadata'].get('scope') != 'identity-recovery'
                or any(value['metadata'].get('target') != backup.target_name(install)
                       for value in (data, keys))):
            raise InstallError('Recovery sets do not belong to this installation')

    def _retry_backup(self, install):
        """Pre-mutation recovery may recapture; retain every failed attempt."""
        backup_id = self.record.get('backup_id', self.id)
        data, keys = self.backups / backup_id, self.recoveries / backup_id
        if not any(path.exists() or path.is_symlink() for path in (data, keys)):
            return
        try:
            self._backup_proof(install)
            return
        except (InstallError, OSError, ValueError):
            pass
        abandoned = self.record.get('abandoned_backup_ids', [])
        if len(abandoned) >= 20:
            raise InstallError('Backup recovery attempt limit reached; preserve partial evidence and inspect host storage')
        self.record['abandoned_backup_ids'] = [*abandoned, backup_id]
        self.record['backup_id'] = str(uuid.uuid4())
        self.save('backup-pending')

    def run(self, apply, finish, *, recovery=False, pre_capture_recover=None, preflight=None,
            pre_apply_check=None):
        # Do not hold Journal's lock across backup.create (it acquires its own).
        with Journal(self.base).locked() as journal:
            install = _installation(journal)
            _pin_runtime(install)
            recipient = install.command(['age-keygen', '-y', self.identity], capture=True).decode().strip()
            service = install.command(['age-keygen', '-y', self.base / 'age.txt'], capture=True).decode().strip()
            if self.pointer.exists() or self.pointer.is_symlink():
                previous = json.loads(regular_bytes(self.pointer))
                if previous.get('instance_id') != journal.document['id']:
                    raise InstallError('Credential operation belongs to a different installation')
                terminal = (previous.get('phase') == 'rotated' or (
                    previous.get('phase') == 'refused' and previous.get('mutations_admitted') is False))
                if not terminal:
                    if previous.get('operation_id') != self.id or previous.get('kind') != self.kind:
                        raise InstallError('Recover the existing credential operation first')
            if self.directory.exists():
                backup_archive.private_directory(self.directory)
                self.record = json.loads(regular_bytes(self.directory / 'record.json'))
                if (self.record.get('operation_id') != self.id or self.record.get('kind') != self.kind
                        or self.record.get('instance_id') != journal.document['id']):
                    raise InstallError('Credential operation does not match the saved approval')
                expected = {self.record.get('recovery_recipient_before', install.config['recovery_recipient'])}
                if self.record.get('phase') == 'rotated':
                    expected.add(install.config['recovery_recipient'])
                if recipient not in expected or recipient == service:
                    raise InstallError('Recovery identity must match this operation independent recovery custody')
                if self.record.get('phase') == 'rotated':
                    return self.record['result']
                if self.record.get('phase') == 'refused':
                    if self.record.get('mutations_admitted') is not False:
                        raise InstallError('Inconsistent refusal evidence; preserve the approved operation')
                    raise InstallError('This operation was refused before credential changes; start a new approved request')
                if not recovery:
                    raise InstallError('Interrupted credential operation requires explicit same-ID recovery')
                if self.record.get('phase') == 'backup-pending':
                    self._retry_backup(install)
            else:
                if recipient != install.config['recovery_recipient'] or recipient == service:
                    raise InstallError('Recovery identity must match the independent recovery recipient')
                if recovery:
                    raise InstallError('There is no credential operation to recover')
                if preflight is not None:
                    preflight(install, self.kind, self.id)
                self.directory.parent.mkdir(mode=0o700, exist_ok=True)
                backup_archive.private_directory(self.directory.parent)
                self.directory.mkdir(mode=0o700)
                self.record = {'schema': 1, 'operation_id': self.id, 'kind': self.kind,
                               'instance_id': journal.document['id'], 'backup_id': self.id,
                               'recovery_recipient_before': recipient, 'mutations_admitted': False}
                self.save('backup-pending')
        if self.record['phase'] == 'backup-pending':
            backup_id = self.record['backup_id']
            if not (self.backups / backup_id).exists() and not (self.recoveries / backup_id).exists():
                backup.create(SimpleNamespace(state_dir=str(self.base), output=str(self.backups / backup_id),
                    recovery_output=str(self.recoveries / backup_id), allow_downtime=True))
            # Partial sets are never deleted or silently overwritten.
        with Journal(self.base).locked() as journal:
            install = _installation(journal)
            _pin_runtime(install)
            self._backup_proof(install)
            install.credential_transaction = self
            install.credential_recovery = recovery
            if recovery:
                install.verify_resource_ownership()
                install.compose('stop', '--timeout', '120', 'console', 'iris', timeout=300)
                self._reconcile_compose(install)
                _maintenance_cleanup(install, self)
                if pre_capture_recover is not None:
                    pre_capture_recover(install, self.kind, self.id)
            sources, _, containers = backup.capture_plan(install)
            self.sources = sources
            self.install = install
            self.save('stopping')
            try:
                _stop(install, containers, recovering_clean_operation=(
                    recovery and self.record.get('initial_clean_stop') is True))
                self.record['initial_clean_stop'] = True
                capture = getattr(install, 'prepare_credential_sources', None)
                if capture is not None:
                    capture(self.sources)
                if pre_apply_check is not None and self.record.get('mutations_admitted') is False:
                    try:
                        pre_apply_check(install, self.kind, self.id)
                    except Exception:
                        # This callback is READ ONLY. No credential write plan
                        # has been admitted, so normal consumers can safely be
                        # restored to let the owner resolve a pending approval
                        # or device drain. Never take this path after apply.
                        self.save('preflight-refused')
                        before_server = getattr(install, 'before_server_start', None)
                        if before_server is not None:
                            before_server()
                        install.compose('up', '-d', '--no-build', '--no-deps', '--force-recreate',
                                        '--wait', '--wait-timeout', '180', 'iris')
                        _before_console_start(install)
                        install.compose('up', '-d', '--no-build', '--no-deps', '--force-recreate',
                                        '--wait', '--wait-timeout', '180', 'console')
                        _consumer_proof(install)
                        self.save('refused')
                        raise InstallError('Stopped-state preflight refused before credential changes; original services verified and resumed') from None
                self.record['mutations_admitted'] = True
                self.save('applying')
                apply(install, self.kind, self.id)
                self.save('restarting-server')
                before_server = getattr(install, 'before_server_start', None)
                if before_server is not None:
                    before_server()
                install.compose('up', '-d', '--no-build', '--no-deps', '--force-recreate',
                                '--wait', '--wait-timeout', '180', 'iris')
                proof = finish(install, self.kind, self.id) or {}
                self.save('restarting-console')
                _before_console_start(install)
                install.compose('up', '-d', '--no-build', '--no-deps', '--force-recreate',
                                '--wait', '--wait-timeout', '180', 'console')
                consumer = _consumer_proof(install)
                if self.record.get('expected_management_sha256') not in (None, consumer['certificate_sha256']):
                    raise InstallError('Console reached an unexpected management certificate')
                proof.update(consumer)
                cleanup = getattr(install, 'cleanup_snapshot_sources', None)
                if cleanup is not None:
                    cleanup(self.sources)
                self.record['result'] = dict(state='rotated', kind=self.kind,
                                            backup_id=self.record['backup_id'], proof=proof)
                self.save('rotated')
                return self.record['result']
            except BaseException:
                if self.record['phase'] == 'refused':
                    raise
                # Recreated containers have new IDs. Address the exact owned
                # service names only after checking ownership, never old IDs.
                try:
                    install.verify_resource_ownership()
                    install.compose('stop', '--timeout', '120', 'console', 'iris', timeout=300)
                    _maintenance_cleanup(install, self)
                finally:
                    self.save('recovery-required')
                raise

    def _reconcile_compose(self, install):
        """Repair only a journal checkpoint interrupted after an approved write."""
        hook = getattr(install, 'reconcile_credential_configuration', None)
        if hook is not None:
            return hook(self)
        path = self.directory / 'write-plan.json'
        if not path.exists():
            return
        for item in json.loads(regular_bytes(path, MAX_SECRET)):
            if item['path'] != str(install.compose_file):
                continue
            current = digest(install.compose_file)
            saved = install.journal.document['completed']['prepared']
            if current == item['after'] and saved == item['before']:
                install.journal.document['completed']['prepared'] = current
                install.journal.save()
            elif current not in (item['before'], item['after']):
                raise InstallError('Deployment configuration differs from approved recovery')

    def stage(self, changes):
        """Save the entire encrypted candidate plan before the first mutation."""
        plan = []
        for index, (path, content, mode, uid, gid) in enumerate(changes):
            path = Path(path).absolute()
            if path.resolve() != path or not any(path == root or root in path.parents
                    for root in [self.base] + [Path(p) for name, p in self.sources.items() if name.startswith('volume-')]):
                raise InstallError('Credential candidate escapes owned storage')
            before = None
            if path.exists():
                _safe_file(path)
                before = _sha(regular_bytes(path, MAX_SECRET))
            encrypted = _encrypt(self.install, content, [self.install.config['recovery_recipient']])
            candidate = self.directory / ('candidate-%d.age' % index)
            atomic_write(candidate, encrypted)
            plan.append(dict(path=str(path), candidate=candidate.name, before=before,
                             after=_sha(content), mode=mode, uid=uid, gid=gid))
        _json(self.directory / 'write-plan.json', plan)

    def apply_plan(self):
        plan = json.loads(regular_bytes(self.directory / 'write-plan.json', MAX_SECRET))
        decoded = []
        for item in plan:
            path = Path(item['path'])
            if path.resolve() != path or not any(path == root or root in path.parents
                    for root in [self.base] + [Path(p) for name, p in self.sources.items() if name.startswith('volume-')]):
                raise InstallError('Saved candidate escapes owned storage')
            if not re.fullmatch(r'candidate-[0-9]+\.age', item['candidate']):
                raise InstallError('Invalid encrypted candidate name')
            actual = None
            if path.exists():
                _safe_file(path)
                actual = _sha(regular_bytes(path, MAX_SECRET))
            if actual not in (item['before'], item['after']):
                # A restarted writer may have durably added state before a
                # later consumer proof failed. Never restore an old snapshot
                # over those writes. Accept only independently decryptable
                # ciphertext under the already committed NEW service identity.
                if self.kind not in ('age-identity', 'age-recovery') or path.suffix != '.age' or actual is None:
                    raise InstallError('Credential changed outside the approved transition')
                public = self.install.command(['age-keygen', '-y', self.base / 'age.txt'], capture=True).decode().strip()
                if public != self.record.get('service_recipient'):
                    raise InstallError('Age transition has an unexpected writer')
                current = regular_bytes(path, MAX_SECRET)
                independent = _replacement_identity(self.install) if self.kind == 'age-recovery' else self.identity
                if (_decrypt(self.install, current, self.base / 'age.txt')
                        != _decrypt(self.install, current, independent)):
                    raise InstallError('Updated encrypted state is not independently recoverable')
                continue
            content = _decrypt(self.install, regular_bytes(self.directory / item['candidate'], MAX_SECRET), self.identity)
            if _sha(content) != item['after']:
                raise InstallError('Encrypted candidate does not match the approved transition')
            decoded.append((item, content))
        for item, content in decoded:
            path = Path(item['path'])
            publish = getattr(self.install, 'publish_credential_file', None)
            if publish is not None:
                publish(path, item['before'], content, item['mode'], item['uid'], item['gid'])
            atomic_write(path, content, item['mode'])
            os.chown(path, item['uid'], item['gid'])
        finalize = getattr(self.install, 'finalize_credential_configuration', None)
        if finalize is not None:
            finalize(self)
        # A modified deployment remains an explicitly installer-owned input.
        self.install.journal.document['completed']['prepared'] = digest(self.install.compose_file)
        if self.kind == 'age-recovery':
            self.install.journal.document['config']['recovery_recipient'] = self.record['recovery_recipient_after']
        self.install.journal.save()


def _pending_preflight(install):
    code = '''import sys
sys.path.insert(0,'/opt/iris/server')
import instruction_keys as k,instruction_rotation as i,tls_rotation as t,trust_rotation as u
r=i._load(k.InstructionPaths.from_env())
s=t._load()
if r and r['state'] in ('awaiting-approval','committing'): raise SystemExit(2)
if s and s['state'] in ('awaiting-approval','approved','committing'): raise SystemExit(2)
for family in u.FAMILIES:
 pending=u._load(family)
 if pending and pending['state'] not in ('published','cancelled'): raise SystemExit(2)
'''
    reader = getattr(install, 'run_readonly', None)
    if reader is not None:
        reader(['python3', '-I', '-B', '-c', code])
    else:
        install.compose('run', '--rm', '--no-deps', '-T', 'iris', 'python3', '-I', '-B', '-c', code)


def _age_apply(install, kind, operation_id):
    tx = install.credential_transaction
    if (tx.directory / 'write-plan.json').exists():
        tx.apply_plan()
        return
    _pending_preflight(install)
    config = Path(tx.sources['volume-iris-config'])
    paths = []
    for path in config.rglob('*'):
        if path.is_symlink():
            raise InstallError('Encrypted configuration contains symbolic links')
        if path.name.endswith('.age'):
            _safe_file(path)
            paths.append(path)
    required = {config / name for name in ('secrets.json.age', 'rpc-secret.age', 'tls/key.pem.age')}
    if not required.issubset(paths):
        raise InstallError('Required encrypted state is missing')
    with _memory(install) as scratch:
        identity = install.command(['age-keygen'], capture=True)
        candidate = scratch / 'identity'
        atomic_write(candidate, identity)
        public = install.command(['age-keygen', '-y', candidate], capture=True).decode().strip()
        recipients = [public, install.config['recovery_recipient']]
        changes = []
        for path in sorted(paths):
            original = regular_bytes(path, MAX_SECRET)
            plain = _decrypt(install, original, install.base / 'age.txt')
            # The recovery key must open CURRENT state too, not just a backup
            # wrapper containing still-unrecoverable ciphertext.
            if _decrypt(install, original, tx.identity) != plain:
                raise InstallError('Independent recovery cannot open current encrypted state')
            encrypted = _encrypt(install, plain, recipients)
            if (_decrypt(install, encrypted, candidate) != plain
                    or _decrypt(install, encrypted, tx.identity) != plain):
                raise InstallError('Age candidate round-trip failed')
            info = path.stat()
            changes.append((path, encrypted, stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid))
        info = _safe_file(install.base / 'age.txt')
        changes.append((install.base / 'age.txt', identity, 0o600, info.st_uid, info.st_gid))
        compose = json.loads(regular_bytes(install.compose_file))
        compose['services']['iris']['environment']['IRIS_AGE_RECIPIENTS'] = ','.join(recipients)
        changes.append((install.compose_file, json.dumps(compose, sort_keys=True).encode(), 0o600, 0, 0))
        tx.record.update(age_files=len(paths), service_recipient=public)
        tx.save('applying')
        tx.stage(changes)
    tx.apply_plan()


def _replacement_identity(install):
    """Resolve ONLY a host-custodian-approved identity; never browser paths."""
    tx = install.credential_transaction
    if 'replacement_identity_path' not in tx.record:
        path = install.base / 'recovery-candidate.json'
        _safe_file(path, private=True)
        candidate = json.loads(regular_bytes(path, 16384))
        if (set(candidate) != {'operation_id', 'identity_path', 'recipient'}
                or candidate.get('operation_id') != tx.id
                or not isinstance(candidate.get('identity_path'), str)
                or not Path(candidate['identity_path']).is_absolute()):
            raise InstallError('Recovery recipient requires a matching local custody approval')
        identity = Path(candidate['identity_path'])
        _safe_file(identity, private=True)
        public = install.command(['age-keygen', '-y', identity], capture=True).decode().strip()
        service = install.command(['age-keygen', '-y', install.base / 'age.txt'], capture=True).decode().strip()
        if (public != candidate['recipient'] or public in (service, install.config['recovery_recipient'])
                or not re.fullmatch(r'age1[0-9a-z]{58}', public)):
            raise InstallError('Select a different independent recovery identity')
        tx.record.update(replacement_identity_path=str(identity), recovery_recipient_after=public,
                         service_recipient=service)
        tx.save('applying')
    identity = Path(tx.record['replacement_identity_path'])
    _safe_file(identity, private=True)
    public = install.command(['age-keygen', '-y', identity], capture=True).decode().strip()
    if public != tx.record['recovery_recipient_after']:
        raise InstallError('Approved replacement recovery identity changed')
    return identity


def _recovery_apply(install, kind, operation_id):
    tx = install.credential_transaction
    independent = _replacement_identity(install)
    if (tx.directory / 'write-plan.json').exists():
        tx.apply_plan()
        return
    _pending_preflight(install)
    config = Path(tx.sources['volume-iris-config'])
    paths = []
    for path in config.rglob('*'):
        if path.is_symlink():
            raise InstallError('Encrypted configuration contains symbolic links')
        if path.name.endswith('.age'):
            _safe_file(path)
            paths.append(path)
    if not {config / name for name in ('secrets.json.age', 'rpc-secret.age', 'tls/key.pem.age')}.issubset(paths):
        raise InstallError('Required encrypted state is missing')
    recipients = [tx.record['service_recipient'], tx.record['recovery_recipient_after']]
    changes = []
    for path in sorted(paths):
        original = regular_bytes(path, MAX_SECRET)
        plain = _decrypt(install, original, install.base / 'age.txt')
        if _decrypt(install, original, tx.identity) != plain:
            raise InstallError('Current recovery identity cannot open the encrypted state')
        encrypted = _encrypt(install, plain, recipients)
        if (_decrypt(install, encrypted, install.base / 'age.txt') != plain
                or _decrypt(install, encrypted, independent) != plain):
            raise InstallError('Replacement recovery recipient round-trip failed')
        info = path.stat()
        changes.append((path, encrypted, stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid))
    compose = json.loads(regular_bytes(install.compose_file))
    compose['services']['iris']['environment']['IRIS_AGE_RECIPIENTS'] = ','.join(recipients)
    changes.append((install.compose_file, json.dumps(compose, sort_keys=True).encode(), 0o600, 0, 0))
    tx.record['age_files'] = len(paths)
    tx.save('applying')
    tx.stage(changes)
    tx.apply_plan()


def _management_apply(install, kind, operation_id):
    tx = install.credential_transaction
    if (tx.directory / 'write-plan.json').exists():
        tx.apply_plan()
        return
    _capability(install, 'management-key.pem.age')
    config = Path(tx.sources['volume-iris-config'])
    with _memory(install) as scratch:
        key, cert = scratch / 'key', scratch / 'cert'
        names = 'DNS:iris,DNS:iris-server,DNS:localhost,IP:127.0.0.1,IP:' + install.config['host']
        san = getattr(install, 'management_tls_san', None)
        if san is not None:
            names = san()
        install.command(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-days', '397',
            '-subj', '/CN=iris', '-addext', 'subjectAltName=' + names,
            '-keyout', key, '-out', cert], timeout=60)
        compose = json.loads(regular_bytes(install.compose_file))
        env = compose['services']['iris']['environment']
        encrypted = _encrypt(install, regular_bytes(key), env['IRIS_AGE_RECIPIENTS'].split(','))
        if (_decrypt(install, encrypted, install.base / 'age.txt') != regular_bytes(key)
                or _decrypt(install, encrypted, tx.identity) != regular_bytes(key)):
            raise InstallError('Management candidate is not independently recoverable')
        cert_bytes = regular_bytes(cert)
        der = install.command(['openssl', 'x509', '-in', cert, '-outform', 'DER'], capture=True)
        tx.record['expected_management_sha256'] = _sha(der)
        tx.save('applying')
        env.update(IRIS_MANAGEMENT_API_KEY='/run/iris/tls/management-key.pem',
                   IRIS_MANAGEMENT_API_GENERATE_CERT='0')
        tx.stage([(config / 'tls/management-key.pem.age', encrypted, 0o600, 10001, 10001),
                  (config / 'tls/management-crt.pem', cert_bytes, 0o644, 10001, 10001),
                  (install.compose_file, json.dumps(compose, sort_keys=True).encode(), 0o600, 0, 0)])
    tx.apply_plan()


def _finish(install, kind, operation_id):
    tx = install.credential_transaction
    if kind in ('age-identity', 'age-recovery'):
        public = install.execute('age-keygen', '-y', getattr(install, 'service_identity_path', '/run/secrets/iris_age_key'), capture=True).decode().strip()
        if public != tx.record.get('service_recipient'):
            raise InstallError('Restarted server did not consume the approved age identity')
        independent = _replacement_identity(install) if kind == 'age-recovery' else tx.identity
        verifier = getattr(install, 'verify_live_age', None)
        if verifier is not None:
            age_files = verifier(tx, independent)
            if type(age_files) is not int or age_files <= 0:
                raise InstallError('Restarted encrypted state verification returned no files')
        else:
            for path in Path(tx.sources['volume-iris-config']).rglob('*.age'):
                _safe_file(path)
                value = regular_bytes(path, MAX_SECRET)
                if _decrypt(install, value, install.base / 'age.txt') != _decrypt(install, value, independent):
                    raise InstallError('Restarted encrypted state is not independently recoverable')
            age_files = tx.record['age_files']
        result = {'age_files': age_files, 'service_recipient': public,
                  'independent_decryption': 'verified'}
        if kind == 'age-recovery':
            result['recovery_recipient'] = tx.record['recovery_recipient_after']
        return result
    return {'dedicated_management_key': 'verified'}


def _maintenance_command(install, tx, *args, **kwargs):
    return install.command(['docker', 'compose', '-p', tx.record['maintenance_project'],
                            '-f', tx.directory / 'maintenance.json', *args], **kwargs)


def _capability(install, marker):
    # Running a fixed read-only command bypasses normal entrypoint startup.
    # An older installed image must refuse BEFORE starting unfrozen services.
    code = "from pathlib import Path; import sys; raise SystemExit(0 if sys.argv[1] in Path('/opt/iris/server/docker-entrypoint.sh').read_text() else 2)"
    reader = getattr(install, 'run_readonly', None)
    if reader is not None:
        reader(['python3', '-I', '-B', '-c', code, marker])
    else:
        install.compose('run', '--rm', '--no-deps', '-T', 'iris', 'python3', '-I', '-B', '-c', code, marker)


def _maintenance_cleanup(install, tx):
    hook = getattr(install, 'maintenance_cleanup', None)
    if hook is not None:
        return hook(tx)
    path = tx.directory / 'maintenance.json'
    if not path.exists():
        return
    if digest(path) != tx.record.get('maintenance_sha256'):
        raise InstallError('Maintenance deployment differs from its approved configuration')
    name = tx.record['maintenance_project']
    if name != install.config['instance'] + '-maintenance-' + tx.id:
        raise InstallError('Unexpected maintenance deployment identity')
    ids = install.command(['docker', 'container', 'ls', '-aq', '--filter', 'name=^/' + name + '$'], capture=True).split()
    for identifier in ids:
        record, = json.loads(install.command(['docker', 'container', 'inspect', identifier.decode()], capture=True))
        if (record['Config'].get('Labels', {}).get('com.cisco.iris.installer') != install.journal.document['id']
                or record['Name'] != '/' + name):
            raise InstallError('Maintenance container ownership differs')
    _maintenance_command(install, tx, 'down', '--timeout', '120', timeout=180)


_SEEDER_SCRIPT = '''import os,sys,json,time,hashlib
sys.path.insert(0,'/opt/iris/server')
import rotate_seeder_announce as r,telemetry
state=os.environ['IRIS_STATE']
rpc=telemetry.make_jsonrpc_caller(os.environ.get('IRIS_RPC',telemetry.DEFAULT_RPC_URL),telemetry._read_rpc_secret(os.environ))
deadline=time.monotonic()+180
while True:
 try:
  targets=r.discover_targets(state,os.environ,rpc)
  break
 except Exception:
  if time.monotonic()>deadline: raise RuntimeError('seeder readiness') from None
  time.sleep(1)
directory=os.path.join(state,'credential-maintenance',sys.argv[1])
os.makedirs(directory,mode=0o700,exist_ok=True)
manifest=os.path.join(directory,'rotation.json')
def fingerprint(): return hashlib.sha256(r._current_announce_token(os.environ['IRIS_SECRETS']).encode()).hexdigest()
if os.path.exists(manifest):
 with open(manifest) as f: record=json.load(f)
 if record.get('phase') not in ('complete','recovered'):
  if r.main(['--maintenance-frozen','--manifest',manifest,'--recover']) != 0: raise RuntimeError('recovery')
 if fingerprint() == sys.argv[2]:
  # A pre-persistence interruption did not rotate anything. Preserve that
  # attempt and approve exactly one replacement attempt under the same ID.
  os.rename(manifest,manifest+'.unrotated-'+str(time.time_ns()))
if not os.path.exists(manifest):
 if r.main(['--maintenance-frozen','--manifest',manifest]) != 0: raise RuntimeError('rotation')
if fingerprint() == sys.argv[2]: raise RuntimeError('credential unchanged')
expected=[r._info_hash(open(t.path,'rb').read()).lower() for t in targets]
if not r.make_swarm_probe(expected,time.time(),timeout=2,retries=180)(): raise RuntimeError('serving proof')
print(json.dumps({'info_hashes':sorted(expected),'credential_changed':True,'isolated_tracker_proof':True}))
'''


def _seeder_apply(install, kind, operation_id):
    hook = getattr(install, 'seeder_maintenance_apply', None)
    if hook is not None:
        return hook(install.credential_transaction)
    tx = install.credential_transaction
    _capability(install, 'IRIS_MAINTENANCE_SEEDER_ONLY')
    path = tx.directory / 'maintenance.json'
    if not path.exists():
        compose = json.loads(regular_bytes(install.compose_file))
        name = install.config['instance'] + '-maintenance-' + operation_id
        spec = compose['services']['iris']
        spec['image'] = install.journal.document['completed']['images'][spec['image']]
        spec.pop('build', None)
        spec.pop('depends_on', None)
        spec.update(container_name=name, ports=[], networks=['maintenance'], restart='no',
                    healthcheck={'disable': True})
        spec['environment'].update(IRIS_MAINTENANCE_SEEDER_ONLY='1',
            IRIS_TRACKER_ANNOUNCE='https://127.0.0.1:6969/announce',
            IRIS_TELEMETRY_CA='/run/iris/tls/maintenance-crt.pem')
        isolated = {'name': name, 'services': {'iris': spec},
            'networks': {'maintenance': {'name': name, 'internal': True,
                'labels': {'com.cisco.iris.installer': install.journal.document['id']}}},
            'volumes': {logical: {'external': True, 'name': value.get('name') or install.config['instance'] + '_' + logical}
                        for logical, value in compose['volumes'].items()},
            'secrets': compose.get('secrets', {})}
        config = Path(tx.sources['volume-iris-config'])
        plain = _decrypt(install, regular_bytes(config / 'secrets.json.age', MAX_SECRET), install.base / 'age.txt')
        if _decrypt(install, regular_bytes(config / 'secrets.json.age', MAX_SECRET), tx.identity) != plain:
            raise InstallError('Seeder state lacks independent recovery')
        try:
            current = json.loads(plain)['seeder']['announce_token']['value']
            if not isinstance(current, str) or not current:
                raise ValueError()
        except (KeyError, TypeError, ValueError):
            raise InstallError('Current seeder credential is unavailable') from None
        encoded = json.dumps(isolated, sort_keys=True).encode()
        code = '''import sys,os,json
sys.path.insert(0,'/opt/iris/server')
import rotate_seeder_announce as r
state=os.environ['IRIS_STATE']
catalog=json.load(open(os.path.join(state,'catalog.json')))
hashes=[]
for image_id,entry in catalog['images'].items():
 if not entry.get('quarantined'):
  hashes.append(r._info_hash(open(os.path.join(state,'torrents',image_id+'.torrent'),'rb').read()).lower())
if not hashes: raise RuntimeError('no published torrent targets')
print(json.dumps(sorted(hashes)))
'''
        hashes = json.loads(install.compose('run', '--rm', '--no-deps', '-T', 'iris',
            'python3', '-I', '-B', '-c', code, capture=True))
        if not isinstance(hashes, list) or not hashes or any(not re.fullmatch('[0-9a-f]{40}', h) for h in hashes):
            raise InstallError('Original canonical torrent identity proof is missing')
        tx.record.update(maintenance_project=name, maintenance_sha256=_sha(encoded),
                         original_seeder_fingerprint=_sha(current.encode()), original_info_hashes=hashes)
        tx.save('applying')
        atomic_write(path, encoded)
    if digest(path) != tx.record['maintenance_sha256']:
        raise InstallError('Maintenance deployment differs from approved configuration')
    try:
        _maintenance_command(install, tx, 'up', '-d', '--no-build', '--no-deps', 'iris')
        output = _maintenance_command(install, tx, 'exec', '-T', 'iris', 'python3', '-I', '-B',
            '-c', _SEEDER_SCRIPT, operation_id, tx.record['original_seeder_fingerprint'],
            capture=True, timeout=700)
        proof = json.loads(output)
        if (proof.get('credential_changed') is not True or proof.get('isolated_tracker_proof') is not True
                or proof.get('info_hashes') != tx.record['original_info_hashes']):
            raise InstallError('Seeder live serving proof is unavailable')
        tx.record['seeder_proof'] = proof
        tx.save('applying')
    finally:
        _maintenance_cleanup(install, tx)


def _seeder_preflight(install, kind, operation_id):
    """Admission is read-only, before backup intent or any service downtime."""
    _capability(install, 'IRIS_MAINTENANCE_SEEDER_ONLY')
    code = '''import os
import rotate_seeder_announce as r,telemetry
rpc=telemetry.make_jsonrpc_caller(os.environ.get('IRIS_RPC',telemetry.DEFAULT_RPC_URL),telemetry._read_rpc_secret(os.environ))
targets=r.discover_targets(os.environ['IRIS_STATE'],os.environ,rpc)
if not targets: raise RuntimeError('no active canonical targets')
print('ready')
'''
    try:
        if install.python(code).strip() != b'ready':
            raise InstallError('readiness')
    except Exception:
        raise InstallError('Seeder rotation requires a published, actively seeded artifact') from None


def _credential_preflight(install, kind, operation_id):
    if kind == 'seeder-announce':
        _seeder_preflight(install, kind, operation_id)
    elif kind == 'management-tls':
        _capability(install, 'management-key.pem.age')
    else:
        _pending_preflight(install)


def _credential_pre_apply_check(install, kind, operation_id):
    if kind in ('age-identity', 'age-recovery'):
        _pending_preflight(install)


def _seeder_finish(install, kind, operation_id):
    tx = install.credential_transaction
    expected = tx.record.get('seeder_proof', {}).get('info_hashes')
    if not expected:
        raise InstallError('Missing isolated seeder rotation proof')
    code = '''import os,sys,json,time,hashlib
sys.path.insert(0,'/opt/iris/server')
os.environ['IRIS_TELEMETRY_CA']=os.path.join(os.environ['IRIS_CONFIG'],'tls/crt.pem')
import rotate_seeder_announce as r,tracker_announce,torrent_personalize
expected=json.loads(sys.argv[1])
catalog=json.load(open(os.path.join(os.environ['IRIS_STATE'],'catalog.json')))
actual=[]
for image_id,entry in catalog['images'].items():
 if entry.get('quarantined'): continue
 data=open(os.path.join(os.environ['IRIS_STATE'],'torrents',image_id+'.torrent'),'rb').read()
 spans=torrent_personalize.scan_top_level(data)
 start,end=spans['announce']
 url=tracker_announce.resolve(os.environ).encode()
 if data[start:end]!=str(len(url)).encode()+b':'+url: raise RuntimeError('public announce not restored')
 actual.append(r._info_hash(data).lower())
if sorted(actual)!=expected: raise RuntimeError('torrent set changed')
if hashlib.sha256(r._current_announce_token(os.environ['IRIS_SECRETS']).encode()).hexdigest()==sys.argv[2]: raise RuntimeError('credential unchanged')
if not r.make_swarm_probe(expected,time.time(),timeout=2,retries=180)(): raise RuntimeError('normal serving proof')
print('verified')
'''
    result = install.execute('python3', '-I', '-B', '-c', code, json.dumps(expected),
                             tx.record['original_seeder_fingerprint'], capture=True, timeout=400)
    if result.strip() != b'verified':
        raise InstallError('Restarted tracker/seeder consumer proof failed')
    return {'seeded_torrents': len(expected), 'credential_changed': True,
            'isolated_tracker_proof': 'verified', 'restarted_tracker_proof': 'verified'}


def rotate(state_dir, backup_dir, recovery_dir, *, kind, operation_id,
           recovery_identity, recovery=False):
    if kind not in KINDS:
        raise InstallError('Unsupported credential rotation family')
    apply = {'age-identity': _age_apply, 'age-recovery': _recovery_apply, 'management-tls': _management_apply,
             'seeder-announce': _seeder_apply}[kind]
    return Transaction(state_dir, backup_dir, recovery_dir, kind=kind,
        operation_id=operation_id, recovery_identity=recovery_identity).run(
            apply, _seeder_finish if kind == 'seeder-announce' else _finish, recovery=recovery,
            preflight=_credential_preflight, pre_apply_check=_credential_pre_apply_check)
