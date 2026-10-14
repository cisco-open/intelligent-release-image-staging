# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Private, same-job cold-capture authority and managed writer quiescence.

This record authorizes settling a capture, never taking it again or adopting an
archive found by name. Callers already hold the worker and installation locks.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

from . import backup_archive, managed_worker
from .state import InstallError, atomic_write, regular_bytes


PROC = Path('/proc')
CGROUP = Path('/sys/fs/cgroup')


def identifier(value):
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise InstallError('Choose the original backup request and backup IDs') from None
    return value


def _process(pid):
    try:
        raw = regular_bytes(PROC / str(pid) / 'stat', 16384).decode()
        fields = raw[raw.rindex(')') + 2:].split()
        return {'pid': pid, 'birth': int(fields[19])}
    except FileNotFoundError:
        return None
    except (ValueError, IndexError, UnicodeError):
        raise InstallError('Capture process identity is unavailable') from None


def _boot():
    value = regular_bytes(PROC / 'sys/kernel/random/boot_id', 128).decode().strip()
    return identifier(value)


def _private(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600 or path.resolve() != path):
        raise InstallError('Unsafe capture recovery authority; preserve the original record')
    return regular_bytes(path, 4 * 1024 * 1024)


def _record_paths(directory):
    """Atomic publication scraps are inert files, not operation authority."""
    records = []
    children = sorted(directory.iterdir())
    if len(children) > backup_archive.MAX_FILES:
        raise InstallError('Capture recovery history exceeds its bounded census')
    for path in children:
        if path.name.startswith('.iris-'):
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or path.resolve() != path
                    or info.st_size > 4 * 1024 * 1024):
                raise InstallError('Unsafe interrupted capture record scratch file; preserve it')
            # Never read, adopt or remove a mkstemp leftover. Only the
            # separately validated UUID.json publication can grant authority.
            continue
        if path.suffix != '.json':
            raise InstallError('Unrecognized capture recovery authority')
        identifier(path.stem)
        records.append(path)
    return records


def _unit_record(installation):
    """Validate against the already held journal; never acquire Journal twice."""
    state, document = installation.base, installation.journal.document
    raw = managed_worker._file(state / managed_worker.RECORD)
    record = json.loads(raw)
    if (record.get('schema') != 1 or record.get('instance_id') != document['id']
            or record.get('target') != document['config']['target']
            or record.get('state_dir') != str(state)
            or record.get('lifecycle_url') != document['config'].get('lifecycle_url')
            or record.get('unit') != 'iris-lifecycle-' + document['id'] + '.service'):
        raise InstallError('Capture worker does not match this managed deployment')
    managed_worker.check_storage(state, record)
    managed_worker._check_unit(state, record)
    unit = managed_worker._file(managed_worker.UNIT_DIRECTORY / record['unit'], mode=0o644)
    runtime = managed_worker._runtime_directory(state, record) / 'iris_installer'
    # No repair/copy during recovery. The running generation must be exactly
    # the recorded managed SDK, not simply a unit with the same name.
    if record.get('runtime') != managed_worker._runtime_manifest():
        raise InstallError('Capture worker generation differs from managed runtime custody')
    for name, expected in record['runtime'].items():
        if hashlib.sha256(managed_worker._file(runtime / name)).hexdigest() != expected:
            raise InstallError('Managed capture runtime changed')
    return record, {'record_sha256': hashlib.sha256(raw).hexdigest(),
                    'unit_sha256': hashlib.sha256(unit).hexdigest()}


def _members(control_group):
    """Read the actual unified hierarchy, including any descendant cgroups."""
    # Do not infer the hierarchy from a unit's name. Verify the mounted kernel
    # filesystem and current process membership before reading its processes.
    mounts = regular_bytes(PROC / 'self/mountinfo', 1024 * 1024).decode().splitlines()
    if not any(line.split(' - ', 1)[0].split()[4] == str(CGROUP)
               and line.split(' - ', 1)[1].split()[0] == 'cgroup2'
               for line in mounts if ' - ' in line):
        raise InstallError('Managed capture recovery needs the unified system cgroup')
    membership = regular_bytes(PROC / 'self/cgroup', 16384).decode().splitlines()
    if membership != ['0::' + control_group]:
        raise InstallError('This process is not the managed capture service')
    root = CGROUP / control_group.lstrip('/')
    if not control_group.startswith('/') or root.resolve() != root:
        raise InstallError('Unsafe managed capture cgroup')
    before = root.stat()
    members, count = set(), 0
    for directory, children, _files in os.walk(root, followlinks=False):
        path = Path(directory)
        info = path.lstat()
        count += 1
        if count > 1024 or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or path.resolve() != path:
            raise InstallError('Managed capture cgroup ownership changed')
        raw = regular_bytes(path / 'cgroup.procs', 64 * 1024).decode().split()
        if any(not value.isdecimal() for value in raw) or len(raw) > 4096:
            raise InstallError('Capture writer census exceeds its bound')
        members.update(map(int, raw))
        for child in children:
            if (path / child).is_symlink():
                raise InstallError('Unsafe managed capture descendant cgroup')
    after = root.stat()
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise InstallError('Managed capture cgroup changed during census')
    if members != {os.getpid()}:
        raise InstallError('An earlier capture writer is still active; recovery did not restart services')
    return {'device': before.st_dev, 'inode': before.st_ino}


def writer_authority(installation, original=None):
    with managed_worker.CAPTURE_PROCESS_LOCK:
        return _writer_authority(installation, original)


def _writer_authority(installation, original=None):
    record, pins = _unit_record(installation)
    output = managed_worker.command(['systemctl', 'show', record['unit'],
        '--property=MainPID,ControlGroup,InvocationID,ActiveState,SubState,FragmentPath,DropInPaths']).decode().splitlines()
    fields = dict(line.split('=', 1) for line in output if '=' in line)
    if (set(fields) != {'MainPID', 'ControlGroup', 'InvocationID', 'ActiveState', 'SubState', 'FragmentPath', 'DropInPaths'}
            or fields['MainPID'] != str(os.getpid()) or fields['ActiveState'] not in ('active', 'activating')
            or fields['SubState'] not in ('running', 'start')
            or not re.fullmatch(r'[0-9a-f]{32}', fields['InvocationID'])
            or fields['InvocationID'] != os.environ.get('INVOCATION_ID')
            or fields['FragmentPath'] != str(managed_worker.UNIT_DIRECTORY / record['unit'])
            or fields['DropInPaths']):
        raise InstallError('Current managed capture service incarnation is not proven')
    command = regular_bytes(PROC / 'self/cmdline', 16384).split(b'\0')
    expected = [b'/usr/bin/python3', b'-I', b'-B',
                os.fsencode(managed_worker._runtime_directory(installation.base, record) / 'launch.py'),
                os.fsencode(installation.base), b'']
    if command != expected:
        raise InstallError('Current process is not the recorded managed worker executable')
    process, boot = _process(os.getpid()), _boot()
    if process is None:
        raise InstallError('Current capture process identity is unavailable')
    if original is not None:
        if any(original.get(key) != value for key, value in pins.items()):
            raise InstallError('Capture service authority changed since the original request')
        if original['boot_id'] == boot and original['process'] != process:
            if _process(original['process']['pid']) == original['process']:
                raise InstallError('The original capture worker is still alive')
    group = _members(fields['ControlGroup'])
    return dict(pins, process=process, boot_id=boot, unit=record['unit'],
                control_group=fields['ControlGroup'], cgroup=group, invocation_id=fields['InvocationID'])


def generation(installation):
    doc = installation.journal.document
    # Mutable topology stop/scale checkpoints are reconciled separately. These
    # values bind security, executable inputs and immutable image/package pins.
    fields = ('prepared', 'images', 'packages', 'kube-images', 'console-image',
              'console-prepared', 'split-prepared', 'split-transport')
    return copy.deepcopy({'instance_id': doc['id'], 'config': doc['config'],
            'source_manifest': doc.get('source_manifest'), 'root_digests': doc.get('root_digests'),
            'completed': {name: doc['completed'][name] for name in fields if name in doc['completed']}})


def guard(state_dir, *, request_id=None, instance_id=None):
    """Ordinary host capture cannot bypass a pending managed capture."""
    directory = Path(state_dir) / 'backup-captures'
    own_set = None
    if directory.exists() or directory.is_symlink():
        backup_archive.private_directory(directory)
        records = _record_paths(directory)
        for path in records:
            record = json.loads(_private(path))
            if (record.get('schema') != 1 or record.get('request_id') != path.stem
                    or instance_id is not None and record.get('generation', {}).get('instance_id') != instance_id):
                raise InstallError('Capture recovery authority differs from this deployment')
            if record.get('phase') not in ('settled-captured', 'settled-failed'):
                if path.stem != request_id:
                    raise InstallError('Recover the interrupted backup capture before another host capture')
                own_set = record['set_id']
    jobs_path = Path(state_dir) / 'lifecycle-jobs.json'
    if jobs_path.exists() or jobs_path.is_symlink():
        jobs = json.loads(_private(jobs_path))
        if not isinstance(jobs, list) or len(jobs) > 100:
            raise InstallError('Capture job history is invalid; preserve it for recovery')
        for job in jobs:
            if (job.get('action') == 'backup' and job.get('state') in ('running', 'recovery-required')
                    and job.get('id') != request_id):
                raise InstallError('Recover the interrupted backup job before another host capture')
    status_path = Path(state_dir) / 'backup-operation.json'
    if status_path.exists() or status_path.is_symlink():
        status = json.loads(_private(status_path))
        if ((status.get('state') == 'stopping' or status.get('restart_required'))
                and (own_set is None or status.get('backup_set_id') != own_set)):
            raise InstallError('An interrupted capture lacks exact same-job authority; preserve it for recovery review')


class Capture:
    """A bounded root-private intent; completed receipts are never guessed."""

    def __init__(self, installation, request_id, backup_id):
        self.installation = installation
        self.request_id, self.backup_id = identifier(request_id), identifier(backup_id)
        root = installation.base / 'backup-captures'
        self.path = root / (self.request_id + '.json')
        self.record = None

    def save(self):
        with managed_worker.CAPTURE_PROCESS_LOCK:
            atomic_write(self.path, (json.dumps(self.record, sort_keys=True) + '\n').encode())

    def begin(self, *, output, recovery, signer, containers, volumes, set_id):
        self.path.parent.mkdir(mode=0o700, exist_ok=True)
        backup_archive.private_directory(self.path.parent)
        if self.path.exists() or self.path.is_symlink():
            raise InstallError('Capture intent already exists; use explicit same-job recovery')
        worker = writer_authority(self.installation)
        parents = {}
        for name, path in (('data', output), ('recovery', recovery)):
            path = Path(path).absolute()
            backup_archive.private_directory(path.parent)
            info = path.parent.stat()
            parents[name] = {'path': str(path), 'parent_device': info.st_dev, 'parent_inode': info.st_ino}
        self.record = {'schema': 1, 'request_id': self.request_id, 'backup_id': self.backup_id,
            'set_id': identifier(set_id), 'phase': 'prepared', 'generation': generation(self.installation),
            'worker': worker, 'destinations': parents, 'containers': containers, 'volumes': volumes,
            'signer_sha256': hashlib.sha256(_private(Path(signer))).hexdigest(),
            'public_sha256': hashlib.sha256(regular_bytes(Path(str(signer) + '.pub'), 4096)).hexdigest(),
            'publications': {}, 'stages': {}, 'restarted': [], 'clean_stop': False}
        hook = getattr(self.installation, 'capture_recovery_authority', None)
        self.record['topology'] = hook(containers, volumes) if hook else None
        self.save()
        self.installation.backup_capture_id = self.request_id
        return self

    def load(self):
        backup_archive.private_directory(self.path.parent)
        self.record = json.loads(_private(self.path))
        if (self.record.get('schema') != 1 or self.record.get('request_id') != self.request_id
                or self.record.get('backup_id') != self.backup_id):
            raise InstallError('Capture recovery IDs differ from original authority')
        return self

    def phase(self, value):
        self.record['phase'] = value
        self.save()

    def stage(self, kind, path):
        parent = Path(self.record['destinations'][kind]['path']).parent
        path = backup_archive.private_directory(Path(path))
        if path.parent != parent or not path.name.startswith('.iris-backup-'):
            raise InstallError('Capture stage is outside its original private destination')
        if kind in self.record['stages']:
            raise InstallError('An archive stage was already admitted; capture cannot be repeated')
        info = path.stat()
        self.record['stages'][kind] = {'path': str(path), 'device': info.st_dev, 'inode': info.st_ino}
        self.save()

    def published(self, kind, envelope):
        path = Path(self.record['destinations'][kind]['path'])
        # Record only a genuine successful create() return, with exact signed
        # bytes. A crash in publication leaves incomplete, retained output.
        receipt = {name: hashlib.sha256(regular_bytes(path / name, 16384)).hexdigest()
                   for name in ('manifest.json', 'manifest.json.sig')}
        receipt['envelope'] = envelope
        self.record['publications'][kind] = receipt
        self.save()

    def check(self):
        if self.record['generation'] != generation(self.installation):
            raise InstallError('Deployment generation changed since interrupted capture')
        writer_authority(self.installation, self.record['worker'])
        for target in self.record['destinations'].values():
            path = Path(target['path'])
            backup_archive.private_directory(path.parent)
            info = path.parent.stat()
            if (info.st_dev, info.st_ino) != (target['parent_device'], target['parent_inode']):
                raise InstallError('Original capture destination storage changed')
        signer = self.installation.base / 'backup-custody/signer'
        if (hashlib.sha256(_private(signer)).hexdigest() != self.record['signer_sha256']
                or hashlib.sha256(regular_bytes(Path(str(signer) + '.pub'), 4096)).hexdigest()
                    != self.record['public_sha256']):
            raise InstallError('Original capture signing authority changed')
        self.installation.backup_capture_id = self.request_id

    def inventory(self):
        hook = getattr(self.installation, 'capture_recovery_inventory', None)
        if hook is not None:
            volumes, containers = hook(self.record['topology'])
        else:
            from .backup import docker_capture_plan
            _sources, volumes, containers = docker_capture_plan(self.installation)
        def stable(container):
            return {key: value for key, value in container.items() if key not in ('running', 'state', 'replicas')}
        if (volumes != self.record['volumes'] or list(map(stable, containers))
                != list(map(stable, self.record['containers']))):
            raise InstallError('Original capture resources changed; no services were restarted')
        for original, current in zip(self.record['containers'], containers):
            if ((original['running'] is False and current['running'] is not False)
                    or 'replicas' in original and current['replicas'] not in (0, original['replicas'])):
                raise InstallError('Original capture service state changed outside stop/start recovery')
        return containers

    def settle(self):
        """Resume health of the original services; do not export or recapture."""
        self.check()
        self.inventory()
        # Verify completed output before restoring service state. Incomplete
        # output is retained, not authenticated/adopted as a successful pair.
        try:
            complete = self.completed()
        except (InstallError, OSError, ValueError):
            # Capture writes never replaced live data. Corrupt/incomplete
            # archives need not keep the unchanged deployment stopped forever.
            # Preserve them and settle FAILED, never waive signature checks.
            complete = False
            self.record['completion_refused'] = True
        self.phase('restarting')
        from .backup import restart_writer
        for original in reversed(self.record['containers']):
            current = next(c for c in self.inventory() if c['service'] == original['service'])
            if not original['running']:
                if current['running']:
                    raise InstallError('A service that was originally stopped was started outside capture')
                continue
            # Explicit restart hooks revalidate identity and health. Checking
            # current state first avoids replaying a completed start after a
            # crash between health proof and its durable marker.
            if not current['running']:
                restart_writer(self.installation, original)
            health = getattr(self.installation, 'capture_recovery_health', None)
            if health is not None:
                health(original)
            else:
                import time
                deadline = time.monotonic() + 180
                while True:
                    record, = json.loads(self.installation.command(
                        ['docker', 'container', 'inspect', original['id']], capture=True))
                    if record['Id'] != original['id'] or not record['State']['Running']:
                        raise InstallError('Original service did not recover after capture')
                    status = record['State'].get('Health', {}).get('Status', 'healthy')
                    if status == 'healthy':
                        break
                    if time.monotonic() >= deadline:
                        raise InstallError('Service health did not recover after interrupted capture')
                    time.sleep(1)
            if original['service'] not in self.record['restarted']:
                self.record['restarted'].append(original['service'])
                self.save()
        self.check()
        observed = self.inventory()
        if any(current['running'] != original['running'] for original, current
               in zip(self.record['containers'], observed)):
            raise InstallError('Original service state has not recovered')
        self.record['restart_required'] = []
        self.phase('settled-captured' if complete else 'settled-failed')
        status = {'state': 'captured' if complete else 'failed', 'backup_set_id': self.record['set_id'],
                  'request_id': self.request_id, 'backup_id': self.backup_id,
                  'containers': self.record['containers'], 'restart_required': []}
        atomic_write(self.installation.base / 'backup-operation.json', json.dumps(status).encode())
        return {'state': 'captured' if complete else 'failed', 'capture_set_id': self.record['set_id'],
                'services_healthy': True, 'recaptured': False, 'partial_output_retained': not complete}

    def completed(self):
        if self.record['clean_stop'] is not True or set(self.record['publications']) != {'data', 'recovery'}:
            return False
        public = self.installation.base / 'backup-custody/signer.pub'
        for kind, receipt in self.record['publications'].items():
            path = Path(self.record['destinations'][kind]['path'])
            for name in ('manifest.json', 'manifest.json.sig'):
                if hashlib.sha256(regular_bytes(path / name, 16384)).hexdigest() != receipt[name]:
                    raise InstallError('Published capture changed; retain the original output')
            if backup_archive.authenticate(path, public) != receipt['envelope']:
                raise InstallError('Published capture differs from its completion receipt')
        return True


def protected_stages(state_dir, backup_dir, recovery_dir):
    """Only exact intent-owned leftover stages, never a temporary-name waiver."""
    with managed_worker.CAPTURE_PROCESS_LOCK:
        return _protected_stages(state_dir, backup_dir, recovery_dir)


def _protected_stages(state_dir, backup_dir, recovery_dir):
    directory = Path(state_dir) / 'backup-captures'
    if not directory.exists() and not directory.is_symlink():
        return {}
    backup_archive.private_directory(directory)
    installation = json.loads(_private(Path(state_dir) / 'installation.json'))
    found = {}
    records = _record_paths(directory)
    roots = {'data': Path(backup_dir), 'recovery': Path(recovery_dir)}
    for path in records:
        request_id = identifier(path.stem)
        record = json.loads(_private(path))
        if (record.get('schema') != 1 or record.get('request_id') != request_id
                or record.get('generation', {}).get('instance_id') != installation['id']):
            raise InstallError('Capture stage belongs to another deployment')
        backup_id = identifier(record.get('backup_id'))
        if set(record.get('stages', {})) - roots.keys():
            raise InstallError('Unrecognized capture stage kind')
        for kind, stage in record.get('stages', {}).items():
            target = record['destinations'][kind]
            if target['path'] != str(roots[kind] / backup_id):
                raise InstallError('Capture stage destination differs from managed custody')
            parent = backup_archive.private_directory(roots[kind])
            info = parent.stat()
            if (info.st_dev, info.st_ino) != (target['parent_device'], target['parent_inode']):
                raise InstallError('Capture stage parent storage changed')
            stage_path = Path(stage['path'])
            if stage_path.parent != parent or not stage_path.name.startswith('.iris-backup-'):
                raise InstallError('Capture stage escapes the original private destination')
            if not stage_path.exists() and not stage_path.is_symlink():
                pass
            else:
                backup_archive.private_directory(stage_path)
                observed = stage_path.stat()
                if (observed.st_dev, observed.st_ino) != (stage['device'], stage['inode']):
                    raise InstallError('Capture stage was replaced; preserve it for inspection')
            if str(stage_path) in found:
                raise InstallError('Capture stages have ambiguous ownership')
            found[str(stage_path)] = {'request_id': request_id, 'backup_id': backup_id,
                                      'device': stage['device'], 'inode': stage['inode']}
    return found
