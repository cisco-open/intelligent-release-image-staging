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
import threading
import time
from types import SimpleNamespace
import uuid

from . import backup, backup_archive
from .state import InstallError, Journal, atomic_write, regular_bytes


class Worker:
    def __init__(self, state_dir, backup_dir, recovery_dir, *, identity=None, extract_dir=None):
        self.state_dir = backup_archive.private_directory(state_dir)
        self.backup_dir = backup_archive.private_directory(backup_dir)
        self.recovery_dir = backup_archive.private_directory(recovery_dir)
        if self.backup_dir == self.recovery_dir:
            raise InstallError("Data and identity recovery storage must be separate")
        self.identity = Path(identity) if identity else None
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

    def status(self):
        with self.lock:
            return {'available': True, 'target': 'single-docker',
                    'storage': 'operator-configured-host-directories',
                    'can_verify': self.identity is not None,
                    'can_extract': self.identity is not None and self.extract_dir is not None,
                    'jobs': json.loads(json.dumps(self.jobs)),
                    'note': 'Keep encrypted copies and pinned backup signer trust off this host. Extraction does not start services or authorize cutover.'}

    def submit(self, request):
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
                first = backup_archive.read(data, self.identity, signer,
                    destination=destination / 'data' if destination else None)
                second = backup_archive.read(recovery, self.identity, signer,
                    destination=destination / 'identity' if destination else None)
                if (first['metadata'].get('backup_set_id') != second['metadata'].get('backup_set_id')
                        or first['metadata'].get('instance_id') != second['metadata'].get('instance_id')):
                    raise InstallError("Data and recovery identity sets do not match")
                result = 'verified-isolated-files' if destination else 'verified-files'
            detail = 'No service cutover performed.' if job['action'] != 'backup' else 'Capture complete; verify recovery separately.'
        except Exception:
            if destination_created:
                # Only this operation's freshly created private UUID directory;
                # never remove a caller's pre-existing extraction or backup.
                try:
                    shutil.rmtree(destination)
                except OSError:
                    pass
            # Never serialize subprocess output, decrypted files or exception
            # representations into the browser-facing journal.
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
                result = worker.status() if request == {'action': 'status'} else worker.submit(request)
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
