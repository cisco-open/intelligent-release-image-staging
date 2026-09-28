# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Deployment-scoped local worker; no shell, paths or secrets accepted over RPC.

Run outside the containers. Only root and the server uid 10001 may connect.
The management tier remains responsible for owner-session/CSRF authorization.
"""

import fcntl
import json
import os
from pathlib import Path
import re
import signal
import shutil
import socket
import socketserver
import stat
import struct
import sys
import threading
import time
from types import SimpleNamespace
import uuid

from . import backup, backup_archive
from .state import InstallError, Journal, atomic_write, regular_bytes


ROTATION_FAMILIES = ('management-tls', 'device-tls', 'peer-ca',
                     'instruction-roots', 'age-identity', 'age-recovery', 'seeder-announce')


class Worker:
    def __init__(self, state_dir, backup_dir, recovery_dir, *, identity=None, extract_dir=None):
        self.state_dir = backup_archive.private_directory(state_dir)
        self.backup_dir = backup_archive.private_directory(backup_dir)
        self.recovery_dir = backup_archive.private_directory(recovery_dir)
        if self.backup_dir == self.recovery_dir:
            raise InstallError("Data and identity recovery storage must be separate")
        self.identity = Path(identity) if identity else None
        self.identity_history = [self.identity] if self.identity else []
        self.operation_identities = {}
        self.custody_record = self.state_dir / 'recovery-access.json'
        if self.custody_record.exists() or self.custody_record.is_symlink():
            info = self.custody_record.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise InstallError('Unsafe recovery access authority')
            access = json.loads(regular_bytes(self.custody_record))
            if (not isinstance(access, dict) or set(access) != {'active', 'identities', 'operations'}
                    or not isinstance(access['identities'], list) or not 1 <= len(access['identities']) <= 101
                    or any(not isinstance(value, str) or not Path(value).is_absolute() for value in access['identities'])
                    or access['active'] not in access['identities'] or not isinstance(access['operations'], dict)
                    or any(not re.fullmatch(r'[0-9a-f-]{36}', key) or value not in access['identities']
                           for key, value in access['operations'].items())):
                raise InstallError('Invalid recovery access authority')
            self.identity = Path(access['active'])
            self.identity_history = [Path(value) for value in access['identities']]
            self.operation_identities = access['operations']
        self.extract_dir = backup_archive.private_directory(extract_dir) if extract_dir else None
        self.record = self.state_dir / 'lifecycle-jobs.json'
        self.lock = threading.Lock()
        self.thread = None
        self.jobs = json.loads(regular_bytes(self.record)) if self.record.exists() else []
        if not isinstance(self.jobs, list) or len(self.jobs) > 100:
            raise InstallError("Lifecycle journal is invalid")
        # A stopped worker is not evidence that its last capture completed.
        for job in self.jobs:
            if job.get('state') == 'running':
                job['state'] = 'recovery-required'
                job['detail'] = 'Worker interrupted. Inspect backup-operation.json and service state before another capture.'
        self.save()

    def save(self):
        atomic_write(self.record, json.dumps(self.jobs, sort_keys=True).encode())

    def save_custody(self):
        atomic_write(self.custody_record, json.dumps({'active': str(self.identity),
            'identities': list(dict.fromkeys(map(str, self.identity_history))),
            'operations': self.operation_identities}, sort_keys=True).encode())

    def status(self):
        with self.lock:
            return {'available': True, 'target': 'single-docker',
                    'storage': 'operator-configured-host-directories',
                    'can_verify': self.identity is not None,
                    'can_extract': self.identity is not None and self.extract_dir is not None,
                    'jobs': json.loads(json.dumps([job for job in self.jobs if job['action'] != 'rotate'])),
                    'note': 'Keep encrypted copies and pinned backup signer trust off this host. Extraction does not start services or authorize cutover.'}

    def rotation_status(self):
        with self.lock:
            return {'available': True, 'target': 'single-docker',
                    'can_rotate': self.identity is not None,
                    'families': list(ROTATION_FAMILIES),
                    'jobs': json.loads(json.dumps([job for job in self.jobs if job['action'] == 'rotate'])),
                    'note': 'Rotation stops this deployment after a verified cold backup. Trust changes also require device removal and package rebuilds.'}

    def submit_rotation(self, request):
        if set(request) != {'action', 'request_id', 'family', 'allow_downtime'}:
            raise InstallError('Unexpected rotation fields')
        request_id, family = request['request_id'], request['family']
        if not isinstance(request_id, str) or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', request_id):
            raise InstallError('Provide a bounded maintenance request ID')
        if not isinstance(family, str) or family not in ROTATION_FAMILIES:
            raise InstallError('Choose a supported credential family')
        if request['allow_downtime'] is not True:
            raise InstallError('Confirm deployment downtime before rotation')
        if not self.identity:
            raise InstallError('Provision independent recovery access before rotation')
        with self.lock:
            previous = next((job for job in self.jobs if job['id'] == request_id), None)
            if previous:
                if previous['action'] != 'rotate' or previous['family'] != family:
                    raise InstallError('Request ID already belongs to a different operation')
                if request['action'] == 'recover-rotation' and previous['state'] == 'recovery-required':
                    if any(job['id'] != request_id and job['state'] in ('running', 'recovery-required') for job in self.jobs):
                        raise InstallError('Another operation requires recovery')
                    previous.update(state='running', detail='Recovering the previously approved operation')
                    self.save()
                    self.thread = threading.Thread(target=self.perform_rotation, args=(previous,),
                        kwargs={'recovery': True}, daemon=False)
                    self.thread.start()
                # Repeating the original request only observes it. Recovery
                # needs its own explicit action and revalidates host custody.
                return {'job_id': previous['id']}
            if request['action'] == 'recover-rotation':
                raise InstallError('Choose an interrupted operation from this deployment')
            if any(job['state'] in ('running', 'recovery-required') for job in self.jobs):
                raise InstallError('A maintenance operation is active or requires recovery')
            if len(self.jobs) >= 100:
                raise InstallError('Lifecycle history limit reached; operator maintenance required')
            job = {'id': request_id, 'action': 'rotate', 'family': family,
                   'state': 'running', 'started_at': int(time.time()), 'detail': '', 'proof': None}
            # Pin the old recovery identity before the job can mutate custody.
            # Recovery after a crash between pointer publication and job
            # completion must still decrypt the ORIGINAL backup and plan.
            self.operation_identities[request_id] = str(self.identity)
            if self.identity not in self.identity_history:
                self.identity_history.append(self.identity)
            self.save_custody()
            self.jobs.append(job)
            self.save()
            self.thread = threading.Thread(target=self.perform_rotation, args=(job,), daemon=False)
            self.thread.start()
            return {'job_id': request_id}

    def perform_rotation(self, job, *, recovery=False):
        try:
            if job['family'] in ('device-tls', 'peer-ca', 'instruction-roots'):
                from . import trust_maintenance as implementation
            else:
                from . import credential_maintenance as implementation
            result = implementation.rotate(self.state_dir, self.backup_dir, self.recovery_dir,
                kind=job['family'], operation_id=job['id'],
                recovery_identity=Path(self.operation_identities.get(job['id'], str(self.identity))), recovery=recovery)
            if job['family'] == 'age-recovery' and result['state'] == 'rotated':
                # Only host-root UI may stage this file; no browser path is
                # accepted. Bind the pointer update to proven public custody.
                candidate_path = self.state_dir / 'recovery-candidate.json'
                info = candidate_path.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                    raise InstallError('Unsafe replacement recovery authority')
                candidate = json.loads(regular_bytes(candidate_path))
                if (candidate.get('operation_id') != job['id']
                        or candidate.get('recipient') != result.get('proof', {}).get('recovery_recipient')):
                    raise InstallError('Replacement recovery authority changed')
                replacement = Path(candidate['identity_path'])
                history = list(dict.fromkeys([str(replacement), *map(str, self.identity_history)]))
                self.identity, self.identity_history = replacement, [Path(value) for value in history]
                self.save_custody()
            state, detail = result['state'], 'Maintenance finished. Review recorded evidence before re-onboarding devices.'
            proof = result.get('proof')
        except Exception as exc:
            reason = str(exc) if isinstance(exc, InstallError) else type(exc).__name__
            print('Credential maintenance failed: ' + reason, file=sys.stderr, flush=True)
            state, detail, proof = 'recovery-required', 'Rotation incomplete. Preserve the protected operation journal and backup; no reset was performed.', None
            operation = self.state_dir / 'credential-operations' / job['id'] / 'record.json'
            # Backends persist this intent before any credential mutation.
            # Failed admission must not create an unrecoverable phantom job.
            if not operation.exists() and not operation.is_symlink():
                state, detail = 'failed', 'Preflight refused the operation before credential changes. Correct deployment or recovery access and start a new request.'
            else:
                try:
                    record = json.loads(regular_bytes(operation))
                    if record.get('phase') == 'refused' and record.get('mutations_admitted') is False:
                        state, detail = 'failed', 'Final preflight refused credential changes. The original deployment was restarted and verified; correct the prerequisite and start a new request.'
                except (OSError, ValueError, InstallError):
                    pass
        with self.lock:
            job.update(state=state, detail=detail, proof=proof, finished_at=int(time.time()))
            self.save()

    def submit(self, request):
        if isinstance(request, dict) and request.get('action') in ('rotate', 'recover-rotation'):
            return self.submit_rotation(request)
        if not isinstance(request, dict) or request.get('action') not in ('backup', 'verify', 'extract'):
            raise InstallError("Unsupported maintenance action")
        action = request['action']
        if set(request) != ({'action', 'request_id', 'allow_downtime'} if action == 'backup'
                            else {'action', 'request_id', 'backup_id'}):
            raise InstallError("Unexpected maintenance fields")
        request_id = request['request_id']
        if not isinstance(request_id, str) or not re.fullmatch(r'[0-9a-f-]{36}', request_id):
            raise InstallError("Provide a bounded maintenance request ID")
        if action == 'backup' and request['allow_downtime'] is not True:
            raise InstallError("Confirm IRIS downtime before capture")
        if action != 'backup' and (not self.identity or (action == 'extract' and not self.extract_dir)):
            raise InstallError("An operator must provision recovery access on the worker first")
        with self.lock:
            for job in self.jobs:
                if job['id'] == request_id:
                    if job['action'] != action or (action != 'backup' and job['backup_id'] != request['backup_id']):
                        raise InstallError("Request ID already belongs to a different operation")
                    return {'job_id': job['id']}
            if any(job['state'] in ('running', 'recovery-required') for job in self.jobs):
                raise InstallError("A maintenance operation is active or requires recovery")
            if len(self.jobs) >= 100:
                raise InstallError("Lifecycle history limit reached; operator maintenance required")
            if action == 'backup':
                if sum(job['action'] == 'backup' for job in self.jobs) >= 20:
                    raise InstallError("Backup count limit reached; archive sets off-host before operator maintenance")
                backup_id = str(uuid.uuid4())
            else:
                backup_id = request['backup_id']
                if (not isinstance(backup_id, str) or not re.fullmatch(r'[0-9a-f-]{36}', backup_id)
                        or not any(job['action'] == 'backup' and job['backup_id'] == backup_id
                                   and job['state'] == 'captured' for job in self.jobs)):
                    raise InstallError("Choose a captured backup from this deployment")
            job = {'id': request_id, 'action': action, 'backup_id': backup_id,
                   'state': 'running', 'started_at': int(time.time()), 'detail': ''}
            self.jobs.append(job)
            self.save()
            self.thread = threading.Thread(target=self.perform, args=(job,), daemon=False)
            self.thread.start()
            return {'job_id': job['id']}

    def perform(self, job):
        destination = None
        destination_created = False
        try:
            backup_id = job['backup_id']
            data = self.backup_dir / backup_id
            recovery = self.recovery_dir / backup_id
            signer = self.state_dir / 'backup-custody/signer.pub'
            if job['action'] == 'backup':
                backup.create(SimpleNamespace(state_dir=self.state_dir, output=data,
                                              recovery_output=recovery, allow_downtime=True))
                result = 'captured'
            else:
                # No service starts, ownership changes, image loads or network.
                destination = self.extract_dir / job['id'] if job['action'] == 'extract' else None
                if destination:
                    destination.mkdir(mode=0o700)
                    destination_created = True
                selected = None
                # Old backup sets remain encrypted to their original recovery
                # custodian. Retain explicitly provisioned access, not secret
                # bytes, across a recipient transition. Verify BOTH before
                # writing any extraction with the selected identity.
                for identity in self.identity_history or [self.identity]:
                    try:
                        first = backup_archive.read(data, identity, signer)
                        second = backup_archive.read(recovery, identity, signer)
                        selected = identity
                        break
                    except (OSError, ValueError, InstallError):
                        continue
                if selected is None:
                    raise InstallError('No provisioned recovery identity opens both backup sets')
                if (first['metadata'].get('scope') != 'managed-deployment-files'
                        or second['metadata'].get('scope') != 'identity-recovery'
                        or first['metadata'].get('target') != 'single-docker'
                        or second['metadata'].get('target') != 'single-docker'
                        or first['metadata'].get('backup_set_id') != second['metadata'].get('backup_set_id')
                        or first['metadata'].get('instance_id') != second['metadata'].get('instance_id')):
                    raise InstallError('Data and recovery identity sets do not match')
                if destination:
                    first = backup_archive.read(data, selected, signer, destination=destination / 'data')
                    second = backup_archive.read(recovery, selected, signer, destination=destination / 'identity')
                if (first['metadata'].get('backup_set_id') != second['metadata'].get('backup_set_id')
                        or first['metadata'].get('instance_id') != second['metadata'].get('instance_id')):
                    raise InstallError("Data and recovery identity sets do not match")
                result = 'verified-isolated-files' if destination else 'verified-files'
            detail = 'No service cutover performed.' if job['action'] != 'backup' else 'Capture complete; verify recovery separately.'
        except Exception as exc:
            if destination_created:
                # Only this operation's freshly created private UUID directory;
                # never remove a caller's pre-existing extraction or backup.
                try:
                    shutil.rmtree(destination)
                except OSError:
                    pass
            # Never serialize subprocess output, decrypted files or exception
            # representations into the browser-facing journal.
            # InstallError text is deliberately operator-safe; keep useful
            # diagnostics on the host without exposing raw command output.
            reason = str(exc) if isinstance(exc, InstallError) else type(exc).__name__
            print('Lifecycle operation failed: ' + reason, file=sys.stderr, flush=True)
            result, detail = 'failed', 'Operation failed. Inspect the protected host state; no reset was performed.'
            if job['action'] == 'backup':
                try:
                    operation = json.loads(regular_bytes(self.state_dir / 'backup-operation.json'))
                    if operation.get('restart_required') or operation.get('state') == 'stopping':
                        result = 'recovery-required'
                except (OSError, ValueError, InstallError):
                    pass
        with self.lock:
            job.update(state=result, detail=detail, finished_at=int(time.time()))
            self.save()


def make_server(path, worker, *, allowed_uids=(0, 10001)):
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.connection.settimeout(5)
            _pid, uid, _gid = struct.unpack('3i', self.connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
            if uid not in allowed_uids:
                return
            try:
                raw = self.rfile.readline(4097)
                if len(raw) > 4096 or not raw.endswith(b'\n'):
                    raise InstallError("Invalid maintenance request")
                request = json.loads(raw)
                result = (worker.status() if request == {'action': 'status'} else
                          worker.rotation_status() if request == {'action': 'rotation-status'} else worker.submit(request))
                response = {'ok': True, 'result': result}
            except (InstallError, ValueError, TypeError) as exc:
                response = {'ok': False, 'error': str(exc) if isinstance(exc, InstallError) else 'Invalid maintenance request'}
            self.wfile.write(json.dumps(response).encode() + b'\n')

    # Linux sockaddr_un limits the address, not the filesystem pathname. Bind
    # through a pinned directory descriptor so a valid long installation path
    # does not fail after its services and packages have already been built.
    # Containers still connect through their short /run/iris-lifecycle mount.
    path = Path(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        server = socketserver.UnixStreamServer(
            '/proc/self/fd/' + str(directory) + '/' + path.name, Handler)
    finally:
        os.close(directory)
    os.chmod(path, 0o660)
    return server


def serve(args):
    if os.geteuid() != 0:
        raise InstallError("Run the lifecycle worker as root on the deployment host")
    state_dir = backup_archive.private_directory(args.state_dir)
    fd = os.open(state_dir / 'lifecycle-worker.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise InstallError("Unsafe lifecycle worker lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise InstallError("A lifecycle worker already owns this deployment") from None
        return _serve_locked(args)
    finally:
        os.close(fd)


def _serve_locked(args):
    with Journal(args.state_dir).locked() as journal:
        if journal.document is None or journal.document['config']['target'] != 'docker':
            raise InstallError("Worker requires an installer-owned Docker deployment")
    worker = Worker(args.state_dir, args.backup_dir, args.recovery_dir,
                    identity=args.recovery_identity, extract_dir=args.extract_dir)
    control = Path(args.state_dir) / 'control'
    if not control.exists() and not control.is_symlink():
        control.mkdir(mode=0o750)
        control.chmod(0o750)
    if control.is_symlink() or control.stat().st_uid != 0 or stat.S_IMODE(control.stat().st_mode) != 0o750:
        raise InstallError("Unsafe lifecycle socket directory")
    os.chown(control, 0, 10001)
    socket_path = control / 'control.sock'
    # Exclusive worker lock is already held. Recover only a root-owned socket,
    # never a symlink or an arbitrary file at the endpoint.
    if socket_path.exists() or socket_path.is_symlink():
        info = socket_path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
            raise InstallError("Unsafe lifecycle endpoint")
        socket_path.unlink()
    server = make_server(socket_path, worker)
    os.chown(socket_path, 0, 10001)
    stop = threading.Event()
    previous = {}
    for sig in (signal.SIGTERM, signal.SIGINT):
        previous[sig] = signal.signal(sig, lambda *_: stop.set())
    server.timeout = 0.5
    try:
        print('Lifecycle worker ready; only this deployment can request bounded maintenance.', flush=True)
        while not stop.is_set():
            server.handle_request()
    finally:
        server.server_close()
        if worker.thread:
            worker.thread.join()
        socket_path.unlink()
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    return 0
