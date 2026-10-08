# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Installer-owned persistent lifecycle service and separately mounted custody.

Only the privileged installer selects paths. Public worker requests cannot
change service configuration, storage targets, executable bytes or identities.
"""

import hashlib
import fcntl
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import uuid

from .backup_archive import private_directory
from .state import InstallError, Journal, atomic_write, regular_bytes


UNIT_DIRECTORY = Path('/etc/systemd/system')
BACKUP_ROOT = Path('/var/lib/iris-backups')
RECOVERY_ROOT = Path('/var/lib/iris-recovery')
RECOVERY_ACCESS_ROOT = Path('/var/lib/iris-worker-recovery')
RECORD = 'worker-service.json'
PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'


def command(argv, *, timeout=120):
    try:
        result = subprocess.run(argv, env={'PATH': PATH, 'LANG': 'C.UTF-8'},
                                stdin=subprocess.DEVNULL, capture_output=True,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise InstallError('Host service command unavailable or timed out; setup is resumable') from None
    if result.returncode:
        raise InstallError('Host service command failed; inspect the protected service journal and retry setup')
    return result.stdout


def _root():
    if os.geteuid() != 0:
        raise InstallError('Manage the lifecycle service as root on the deployment host')


def _path(value):
    path = Path(value).absolute()
    if path == Path('/') or path.resolve() != path or any(ord(c) < 32 for c in str(path)):
        raise InstallError('Choose a dedicated absolute path without symlinks or control characters')
    # Pinning a child beneath a directory another account can rename is unsafe.
    for parent in (path, *path.parents):
        if not parent.exists():
            continue
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022 and not (info.st_mode & stat.S_ISVTX)):
            raise InstallError('Worker paths need root-owned directories without writable ancestors')
    return path


def mount_identity(path):
    """Use persistent filesystem identity; Linux device numbers can change at boot."""
    path = _path(path)
    result = json.loads(command(['findmnt', '--json', '--target', str(path),
                                 '--output', 'TARGET,SOURCE,FSTYPE,UUID']))
    rows = result.get('filesystems', [])
    if len(rows) != 1 or not all(isinstance(rows[0].get(k), str) for k in ('target', 'source', 'fstype')):
        raise InstallError('Storage mount identity is unavailable')
    row = rows[0]
    if row['fstype'] in ('tmpfs', 'ramfs', 'overlay', 'squashfs'):
        raise InstallError('Choose persistent mounted storage for backup custody')
    identity = {'mount': row['target'], 'filesystem': row['fstype'],
                'source': ('UUID=' + row['uuid']) if row.get('uuid') else row['source']}
    return dict(identity, inode=path.stat().st_ino)


def _file(path, *, mode=0o600):
    info = path.lstat()
    if (path.resolve() != path or not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode):
        raise InstallError('Unsafe managed service file; preserve it for inspection')
    return regular_bytes(path, 4 * 1024 * 1024)


def _installation(state):
    with Journal(state).locked() as journal:
        if journal.document is None:
            raise InstallError('Managed worker requires an installer-owned deployment')
        from .deploy import validate_config
        validate_config(journal.document['config'])
        identifier = journal.document.get('id')
        try:
            if str(uuid.UUID(identifier)) != identifier:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise InstallError('Installation identity is invalid') from None
        return identifier, dict(journal.document['config'])


def _load(state):
    record = json.loads(_file(state / RECORD))
    identifier, config = _installation(state)
    if (record.get('schema') != 1 or record.get('instance_id') != identifier
            or record.get('target') != config['target']
            or record.get('state_dir') != str(state)
            or record.get('lifecycle_url') != config.get('lifecycle_url')):
        raise InstallError('Managed service does not match this pinned deployment')
    if record.get('unit') != 'iris-lifecycle-' + identifier + '.service':
        raise InstallError('Managed service unit identity changed')
    return record


def _save(state, record):
    atomic_write(state / RECORD, (json.dumps(record, sort_keys=True, indent=2) + '\n').encode())


def _provision_directory(path, identifier):
    """Create only our child; never chmod or adopt an existing storage tree."""
    if not path.exists() and not path.is_symlink():
        path.mkdir(mode=0o700)
    private_directory(path)
    marker = path / '.iris-storage.json'
    expected = json.dumps({'instance_id': identifier}, sort_keys=True).encode()
    if marker.exists() or marker.is_symlink():
        if _file(marker) != expected:
            raise InstallError('Backup target belongs to another deployment')
    else:
        if any(path.iterdir()):
            raise InstallError('Choose an empty new backup target; existing content will not be adopted')
        atomic_write(marker, expected)


def check_storage(state, record):
    for kind in ('backup', 'recovery'):
        target = record['storage'][kind]
        if mount_identity(target['root']) != target['identity']:
            raise InstallError('Backup custody mount changed or is unavailable; restore the recorded storage before retrying')
        directory = private_directory(target['directory'])
        marker = json.loads(_file(directory / '.iris-storage.json'))
        if marker != {'instance_id': record['instance_id']}:
            raise InstallError('Backup custody ownership changed')
    private_directory(state / 'isolated-restores')


def _runtime_source():
    return Path(__file__).resolve().parent


def _runtime_manifest():
    return {path.name: hashlib.sha256(regular_bytes(path, 4 * 1024 * 1024)).hexdigest()
            for path in sorted(_runtime_source().glob('*.py'))}


def _runtime_directory(state, record):
    revision = hashlib.sha256(json.dumps(record['runtime'], sort_keys=True).encode()).hexdigest()
    return state / 'worker-runtime' / revision


def _runtime(state, record):
    directory = _runtime_directory(state, record)
    package = directory / 'iris_installer'
    for path in (state / 'worker-runtime', directory, package):
        path.mkdir(mode=0o700, exist_ok=True)
        private_directory(path)
    source = _runtime_source()
    manifest = record['runtime']
    for name, expected in manifest.items():
        destination = package / name
        if destination.exists() or destination.is_symlink():
            if hashlib.sha256(_file(destination)).hexdigest() != expected:
                raise InstallError('Pinned worker runtime changed; preserve the service for inspection')
        else:
            data = regular_bytes(source / name, 4 * 1024 * 1024)
            if hashlib.sha256(data).hexdigest() != expected:
                raise InstallError('Resume setup with the same installer runtime')
            atomic_write(destination, data)
    launcher = ("# Copyright 2026 Cisco Systems, Inc. and its affiliates\n"
                "# SPDX-License-Identifier: Apache-2.0\n"
                "import sys\nfrom pathlib import Path\nfrom types import SimpleNamespace\n"
                "sys.path.insert(0, str(Path(__file__).resolve().parent))\n"
                "from iris_installer.managed_worker import serve_managed\n"
                "raise SystemExit(serve_managed(SimpleNamespace(state_dir=Path(sys.argv[1]))))\n").encode()
    target = directory / 'launch.py'
    if target.exists() or target.is_symlink():
        if _file(target) != launcher:
            raise InstallError('Pinned worker launcher changed')
    else:
        atomic_write(target, launcher)


def _quote(value, *, environment=True):
    # systemd unit syntax is not a shell. Escape its specifier and environment
    # expansion as well as quotes; filenames are never interpreted as commands.
    value = str(value).replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%')
    return '"' + (value.replace('$', '$$') if environment else value) + '"'


def unit_bytes(state, record):
    roots = [record['storage'][kind]['root'] for kind in ('backup', 'recovery')]
    lines = ['# Copyright 2026 Cisco Systems, Inc. and its affiliates',
             '# SPDX-License-Identifier: Apache-2.0', '[Unit]',
             'Description=IRIS lifecycle worker ' + record['instance_id'],
             'Wants=network-online.target', 'After=network-online.target',
             'RequiresMountsFor=' + ' '.join(_quote(path, environment=False) for path in (str(state), *roots)),
             'StartLimitIntervalSec=60', 'StartLimitBurst=5', '', '[Service]',
             'Type=notify', 'NotifyAccess=main', 'User=root', 'Group=root',
             'UMask=0077',
             'ExecStart=/usr/bin/python3 -I -B ' + _quote(_runtime_directory(state, record) / 'launch.py') + ' ' + _quote(state),
             'Environment="PATH=' + PATH + '"', 'Environment=PYTHONDONTWRITEBYTECODE=1',
             'Restart=on-failure', 'RestartSec=5', 'TimeoutStartSec=90',
             # Graceful stop waits for already accepted cold-capture/rotation
             # transactions. Killing their children can strand stopped writers.
             'TimeoutStopSec=infinity', 'KillMode=mixed', 'NoNewPrivileges=yes',
             'ProtectSystem=full', 'ProtectKernelTunables=yes', 'ProtectKernelModules=yes',
             'ProtectControlGroups=yes', 'RestrictSUIDSGID=yes',
             'StandardOutput=journal', 'StandardError=journal', '', '[Install]',
             'WantedBy=multi-user.target', '']
    return '\n'.join(lines).encode()


def _check_unit(state, record):
    if _file(UNIT_DIRECTORY / record['unit'], mode=0o644) not in {
            unit_bytes(state, record), _legacy_unit_bytes(state, record)}:
        raise InstallError('Managed system service changed; preserve its unit for inspection')


def _legacy_unit_bytes(state, record):
    # The first managed-service candidate incorrectly used ExecStart's quoting
    # for this single-path directive. Admit only those exact installer bytes
    # for repair; a changed or foreign unit remains an error.
    roots = [record['storage'][kind]['root'] for kind in ('backup', 'recovery')]
    correct_mounts = 'RequiresMountsFor=' + ' '.join(_quote(path, environment=False) for path in (str(state), *roots))
    former_mounts = 'RequiresMountsFor=' + ' '.join(_quote(path) for path in (str(state), *roots))
    return unit_bytes(state, record).replace(correct_mounts.encode(), former_mounts.encode(), 1).replace(b'UMask=0077\n',
        ('UMask=0077\nWorkingDirectory=' + _quote(state) + '\n').encode(), 1)


@contextmanager
def _service_lock(state):
    fd = os.open(state / 'worker-service.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise InstallError('Unsafe managed service setup lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise InstallError('Another managed service setup is already running') from None
        yield
    finally:
        os.close(fd)


def setup(args):
    _root()
    state = private_directory(args.state_dir)
    with _service_lock(state):
        return _setup(args)


def _default_root(path):
    _path(path)
    if not path.exists() and not path.is_symlink():
        path.mkdir(mode=0o700)
    return private_directory(path)


def _select_recovery_identity(state, identifier, config, roots, value):
    """Explicit file selection permits a protected host copy, never export."""
    from .maintenance import recovery_identity, _identity_source_uids
    source, recipient = recovery_identity(value, allow_invoking_user=True)
    if recipient != config['recovery_recipient']:
        raise InstallError('Select the independent identity matching the installed recovery recipient')
    if any(source == path or path in source.parents for path in (state, *roots)):
        raise InstallError('Keep recovery identity outside deployment and backup custody')
    if source.stat().st_uid == 0:
        _path(source.parent)
        return source
    # The calling account can change its selected file. Read its bounded native
    # age identity into protected host custody, then validate that exact copy.
    # No key is copied unless the operator explicitly selected recovery access.
    root = _default_root(RECOVERY_ACCESS_ROOT)
    directory = root / identifier
    directory.mkdir(mode=0o700, exist_ok=True)
    private_directory(directory)
    destination = directory / (recipient + '.age')
    if destination.exists() or destination.is_symlink():
        if recovery_identity(destination)[1] != recipient:
            raise InstallError('Protected recovery identity changed; preserve it for inspection')
        return destination
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in _identity_source_uids()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 8192):
            raise InstallError('Recovery source changed after selection')
        private = stream.read(8193)
    if len(private) > 8192:
        raise InstallError('Recovery identity exceeds its size limit')
    atomic_write(destination, private)
    try:
        if recovery_identity(destination)[1] != recipient:
            raise InstallError('Recovery identity changed after selection')
    except BaseException:
        destination.unlink()
        raise
    return destination


def _setup(args):
    """Create/resume one service; private recovery access requires explicit selection."""
    _root()
    state = private_directory(args.state_dir)
    _path(state)
    identifier, config = _installation(state)
    record_path = state / RECORD
    if record_path.exists() or record_path.is_symlink():
        record = _load(state)
        for name in ('backup', 'recovery'):
            supplied = getattr(args, name + '_root', None)
            if supplied is not None and str(_path(supplied)) != record['storage'][name]['root']:
                raise InstallError('Resume uses the recorded backup targets; a different target requires a reviewed migration')
        for name in ('recovery_identity', 'listen_address'):
            supplied = getattr(args, name, None)
            accepted = {record.get(name)}
            if name == 'recovery_identity':
                accepted.add(record.get('recovery_identity_source'))
            if supplied is not None and str(supplied) not in accepted:
                raise InstallError('Resume uses the recorded worker custody and listener')
        if getattr(args, 'refresh_runtime', False) and record['runtime'] != _runtime_manifest():
            _check_unit(state, record)
            # Stop waits for accepted work before changing executable custody.
            active = command(['systemctl', 'show', record['unit'], '--property=ActiveState']).decode()
            if 'ActiveState=inactive' not in active.splitlines() and 'ActiveState=failed' not in active.splitlines():
                command(['systemctl', 'stop', record['unit']], timeout=3600)
            record['previous_unit_sha256'] = hashlib.sha256(
                _file(UNIT_DIRECTORY / record['unit'], mode=0o644)).hexdigest()
            record['runtime'] = _runtime_manifest()
            record['phase'] = 'runtime-update'
            _save(state, record)
    else:
        pending = state / 'worker-setup-request.json'
        if pending.exists() or pending.is_symlink():
            saved = json.loads(_file(pending))
            if saved.get('instance_id') != identifier:
                raise InstallError('Pending worker setup belongs to another deployment')
            args = SimpleNamespace(**vars(args))
            for name, value in saved['options'].items():
                supplied = getattr(args, name, None)
                if supplied is not None and str(supplied) != value:
                    raise InstallError('Worker setup options changed after installation review')
                setattr(args, name, value)
        roots = {kind: _path(getattr(args, kind + '_root', None) or _default_root(default))
                 for kind, default in (('backup', BACKUP_ROOT), ('recovery', RECOVERY_ROOT))}
        identities = {kind: mount_identity(path) for kind, path in roots.items()}
        if (roots['backup'] == roots['recovery'] or roots['backup'] in roots['recovery'].parents
                or roots['recovery'] in roots['backup'].parents
                or any(path == state or state in path.parents or path in state.parents for path in roots.values())):
            raise InstallError('Use separate data and identity recovery directories outside deployment state')
        listen = getattr(args, 'listen_address', None)
        if listen is not None:
            import ipaddress
            try:
                if ipaddress.ip_address(listen).version != 4:
                    raise ValueError()
            except ValueError:
                raise InstallError('Choose an explicit IPv4 worker bind address') from None
            if config['target'] != 'kubernetes':
                raise InstallError('Network binding applies only to Kubernetes')
        identity = getattr(args, 'recovery_identity', None)
        if identity is not None:
            identity = _select_recovery_identity(state, identifier, config, list(roots.values()), identity)
        record = {'schema': 1, 'instance_id': identifier, 'target': config['target'],
                  'state_dir': str(state), 'lifecycle_url': config.get('lifecycle_url'),
                  'unit': 'iris-lifecycle-' + identifier + '.service',
                  'listen_address': listen, 'recovery_identity': str(identity) if identity else None,
                  'recovery_identity_source': str(getattr(args, 'recovery_identity', None)) if identity else None,
                  'storage_layout': ('separate-filesystems' if roots['backup'].stat().st_dev !=
                                     roots['recovery'].stat().st_dev else 'colocated-filesystem'),
                  'phase': 'provisioning', 'storage': {},
                  'runtime': _runtime_manifest()}
        for kind, root in roots.items():
            record['storage'][kind] = {'root': str(root), 'identity': identities[kind],
                                      'directory': str(root / ('iris-' + identifier))}
        _save(state, record)
    # Revalidate roots before creating any child, including a resumed setup.
    for target in record['storage'].values():
        if mount_identity(target['root']) != target['identity']:
            raise InstallError('Recorded backup mount changed; reconnect its storage before resuming')
        _provision_directory(Path(target['directory']), identifier)
    (state / 'isolated-restores').mkdir(mode=0o700, exist_ok=True)
    check_storage(state, record)
    _runtime(state, record)
    unit = UNIT_DIRECTORY / record['unit']
    if unit.exists() or unit.is_symlink():
        actual = _file(unit, mode=0o644)
        if actual != unit_bytes(state, record):
            if (hashlib.sha256(actual).hexdigest() != record.get('previous_unit_sha256')
                    and actual != _legacy_unit_bytes(state, record)):
                raise InstallError('Managed system service changed; preserve its unit for inspection')
            atomic_write(unit, unit_bytes(state, record), 0o644)
    else:
        atomic_write(unit, unit_bytes(state, record), 0o644)
    record['phase'] = 'service-written'
    _save(state, record)
    command(['systemctl', 'daemon-reload'])
    command(['systemctl', 'enable', '--now', record['unit']])
    wait_ready(state, record)
    record['phase'] = 'ready'
    record.pop('previous_unit_sha256', None)
    _save(state, record)
    result = inspect(state)
    print(json.dumps(result, sort_keys=True))
    return 0


def _probe(state, record, *, network=True):
    from .maintenance import MaintenanceClient
    result = MaintenanceClient(state).call({'action': 'status'})
    if result.get('available') is not True:
        raise InstallError('Managed worker has not become ready')
    if network and record['target'] == 'kubernetes':
        from .lifecycle_network import endpoint
        host, port = endpoint(record['lifecycle_url'])
        custody = state / 'lifecycle-tls'
        context = ssl.create_default_context(cafile=str(custody / 'ca.crt'))
        context.load_cert_chain(str(custody / 'client.crt'), str(custody / 'client.key'))
        address = record.get('listen_address') or host
        if address == '0.0.0.0':
            address = '127.0.0.1'
        body = b'{"action":"status"}'
        with socket.create_connection((address, port), timeout=5) as plain:
            with context.wrap_socket(plain, server_hostname=host) as secure:
                request = (b'POST /v1/lifecycle HTTP/1.0\r\nHost: ' + host.encode('ascii') +
                           b'\r\nContent-Type: application/json\r\nContent-Length: ' +
                           str(len(body)).encode() + b'\r\n\r\n' + body)
                secure.sendall(request)
                from http.client import HTTPResponse
                response = HTTPResponse(secure)
                response.begin()
                payload = response.read(128 * 1024 + 1)
                if response.status != 200 or len(payload) > 128 * 1024:
                    raise InstallError('Managed Kubernetes mutual TLS readiness failed')
                observed = json.loads(payload)
                if observed.get('ok') is not True or observed.get('result', {}).get('available') is not True:
                    raise InstallError('Managed Kubernetes worker is not ready')
    return result


def wait_ready(state, record, *, timeout=30, network=True):
    deadline = time.monotonic() + timeout
    while True:
        try:
            return _probe(state, record, network=network)
        except (InstallError, OSError, ValueError):
            if time.monotonic() >= deadline:
                raise InstallError('Worker readiness failed; service and custody are preserved for host recovery') from None
            time.sleep(0.25)


def inspect(state):
    """Safe host/UI status. Never return identity paths or subprocess diagnostics."""
    _root()
    state = private_directory(state)
    if not (state / RECORD).exists() and not (state / RECORD).is_symlink():
        return {'managed': False, 'state': 'setup-required'}
    record = _load(state)
    if not (UNIT_DIRECTORY / record['unit']).exists():
        return {'managed': True, 'state': record['phase'], 'active': False,
                'enabled': False, 'storage_ready': False, 'unix_ready': False,
                'mtls_ready': False if record['target'] == 'kubernetes' else None}
    _check_unit(state, record)
    observed = command(['systemctl', 'show', record['unit'], '--property=ActiveState,SubState,UnitFileState']).decode()
    fields = dict(line.split('=', 1) for line in observed.splitlines() if '=' in line)
    result = {'managed': True, 'state': record['phase'], 'unit': record['unit'],
              'active': fields.get('ActiveState') == 'active',
              'enabled': fields.get('UnitFileState') == 'enabled',
              'storage_ready': False, 'unix_ready': False,
              'mtls_ready': None if record['target'] != 'kubernetes' else False,
              'recovery_access': bool(record.get('recovery_identity')),
              'custody': record['storage_layout'],
              'off_host_protection': 'not-proven',
              'storage_note': 'Local directories preserve separate archive custody; copy both encrypted sets and signer trust to independently protected storage.'}
    try:
        check_storage(state, record)
        result['storage_ready'] = True
        _probe(state, record, network=False)
        result['unix_ready'] = True
        if record['target'] == 'kubernetes':
            _probe(state, record)
            result['mtls_ready'] = True
    except (InstallError, OSError, ValueError):
        result['state'] = 'recovery-required'
    return result


def status(args):
    print(json.dumps(inspect(args.state_dir), sort_keys=True))
    return 0


def configure(state_dir, *, backup_root=None, recovery_root=None,
              recovery_identity=None, listen_address=None, refresh_runtime=False):
    """Host terminal helper: selected paths stay local and never enter web RPC."""
    setup(SimpleNamespace(state_dir=state_dir, backup_root=backup_root,
        recovery_root=recovery_root, recovery_identity=recovery_identity,
        listen_address=listen_address, refresh_runtime=refresh_runtime))
    return inspect(state_dir)


def remember_options(args):
    """Retain initial public setup choices while waiting for offline approval."""
    _root()
    state = private_directory(args.state_dir)
    identifier, _config = _installation(state)
    options = {name: str(getattr(args, name)) for name in
               ('backup_root', 'recovery_root', 'recovery_identity', 'listen_address')
               if getattr(args, name, None) is not None}
    if not options or (state / RECORD).exists():
        return
    path = state / 'worker-setup-request.json'
    if path.exists() or path.is_symlink():
        previous = json.loads(_file(path))
        if previous.get('instance_id') != identifier or any(
                name in previous['options'] and previous['options'][name] != value
                for name, value in options.items()):
            raise InstallError('Worker setup options changed after installation review')
        options = dict(previous['options'], **options)
    atomic_write(path, json.dumps({'instance_id': identifier, 'options': options}, sort_keys=True).encode())


def configure_recovery(state_dir, identity_path=None):
    """Explicit host custody change, retaining paths needed by older backups."""
    _root()
    state = private_directory(state_dir)
    with _service_lock(state):
        return _configure_recovery(state, identity_path)


def _configure_recovery(state, identity_path):
    _apply_recovery_intent(state)
    record = _load(state)
    _check_unit(state, record)
    check_storage(state, record)
    selected = None
    if identity_path is not None:
        _identifier, config = _installation(state)
        roots = [Path(row['root']) for row in record['storage'].values()]
        selected = _select_recovery_identity(state, _identifier, config, roots, identity_path)
    command(['systemctl', 'stop', record['unit']], timeout=3600)
    custody = state / 'recovery-access.json'
    archived = state / 'worker-disabled-recovery-access.json'
    if selected is None:
        if custody.exists() or custody.is_symlink():
            atomic_write(archived, _file(custody))
        access = None
    else:
        previous = (custody if custody.exists() or custody.is_symlink() else archived)
        access = json.loads(_file(previous)) if previous.exists() else {
            'active': str(selected), 'identities': [], 'operations': {}}
        access['active'] = str(selected)
        access['identities'] = list(dict.fromkeys([*access['identities'], str(selected)]))
        if len(access['identities']) > 101:
            raise InstallError('Recovery custody history is full; preserve access to existing backups')
    replacement = dict(record, recovery_identity=str(selected) if selected else None,
                       recovery_identity_source=str(identity_path) if selected else None)
    old_access = _file(custody) if custody.exists() or custody.is_symlink() else None
    intent = {'instance_id': record['instance_id'], 'record': replacement, 'access': access,
              'old_record_sha256': hashlib.sha256(_file(state / RECORD)).hexdigest(),
              'old_access_sha256': hashlib.sha256(old_access).hexdigest() if old_access is not None else None}
    atomic_write(state / 'worker-custody-intent.json', json.dumps(intent, sort_keys=True).encode())
    _apply_recovery_intent(state)
    record = replacement
    command(['systemctl', 'start', record['unit']])
    wait_ready(state, record, network=False)
    return inspect(state)


def _apply_recovery_intent(state):
    path = state / 'worker-custody-intent.json'
    if not path.exists() and not path.is_symlink():
        return
    intent = json.loads(_file(path))
    current = _load(state)
    if intent.get('instance_id') != current['instance_id']:
        raise InstallError('Recovery custody intent belongs to another deployment')
    desired = (json.dumps(intent['record'], sort_keys=True, indent=2) + '\n').encode()
    if hashlib.sha256(_file(state / RECORD)).hexdigest() not in {
            intent['old_record_sha256'], hashlib.sha256(desired).hexdigest()}:
        raise InstallError('Recovery custody service record changed after review')
    custody = state / 'recovery-access.json'
    existing = _file(custody) if custody.exists() or custody.is_symlink() else None
    replacement = json.dumps(intent['access'], sort_keys=True).encode() if intent['access'] else None
    digest = lambda value: hashlib.sha256(value).hexdigest() if value is not None else None
    if digest(existing) not in {intent['old_access_sha256'], digest(replacement)}:
        raise InstallError('Recovery custody authority changed after review')
    atomic_write(state / RECORD, desired)
    if replacement is None:
        if existing is not None:
            custody.unlink()
    else:
        atomic_write(custody, replacement)
    path.unlink()
    fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def configure_restore_signer(state_dir, public_key_path):
    """Pin only an independently selected PUBLIC backup signer on this host."""
    _root()
    state = private_directory(state_dir)
    with _service_lock(state):
        return _configure_restore_signer(state, public_key_path)


def _configure_restore_signer(state, public_key_path):
    record = _load(state)
    _check_unit(state, record)
    source = Path(public_key_path).absolute()
    if source.resolve() != source or source == state or state in source.parents:
        raise InstallError('Select the independently held public backup signer outside deployment state')
    info = source.lstat()
    from .maintenance import _identity_source_uids
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in _identity_source_uids() or info.st_nlink != 1
            or info.st_mode & 0o022):
        raise InstallError('Public signer must be a protected root or caller-owned regular file')
    data = regular_bytes(source, 4096)
    # Validate the wire encoding through OpenSSH as well as the textual type.
    if len(data.splitlines()) != 1 or len(data.split()) < 2 or data.split()[0] != b'ssh-ed25519':
        raise InstallError('Choose one OpenSSH Ed25519 public backup signer')
    canonical = b' '.join(data.split()[:2]) + b'\n'
    with tempfile.TemporaryDirectory(prefix='public-signer-', dir=state) as scratch:
        candidate = Path(scratch) / 'signer.pub'
        atomic_write(candidate, canonical)
        command(['ssh-keygen', '-l', '-f', str(candidate)], timeout=15)
    installed = state / 'backup-custody/signer.pub'
    if installed.exists() and regular_bytes(installed, 4096).split()[:2] != canonical.split():
        raise InstallError('Independent public signer does not match this deployment backup signer')
    jobs = state / 'lifecycle-jobs.json'
    if jobs.exists() and any(row.get('state') in ('running', 'recovery-required')
                             for row in json.loads(_file(jobs))):
        raise InstallError('Finish or recover active lifecycle work before changing signer trust')
    directory = state / 'restore-custody'
    directory.mkdir(mode=0o700, exist_ok=True)
    private_directory(directory)
    target = directory / 'signer.pub'
    if target.exists() or target.is_symlink():
        if _file(target) != canonical:
            raise InstallError('Independent backup signer is already pinned; preserve its trust')
    else:
        atomic_write(target, canonical)
    return {'configured': True, 'signer_sha256': hashlib.sha256(canonical).hexdigest()}


def action(args):
    _root()
    if args.action not in ('start', 'stop', 'restart'):
        raise InstallError('Choose start, stop or restart for this managed service')
    state = private_directory(args.state_dir)
    record = _load(state)
    _check_unit(state, record)
    if args.action != 'stop':
        check_storage(state, record)
    command(['systemctl', args.action, record['unit']], timeout=3600)
    if args.action != 'stop':
        wait_ready(state, record, network=False)
    return status(args)


def serve_managed(args):
    _root()
    state = private_directory(args.state_dir)
    _apply_recovery_intent(state)
    record = _load(state)
    check_storage(state, record)
    _runtime(state, record)
    from . import lifecycle_worker
    original = lifecycle_worker.Worker

    class ManagedWorker(original):
        def submit(self, request):
            check_storage(state, record)
            return super().submit(request)

        def submit_transport(self, request):
            # Transport recovery remains available even when backup disks are
            # detached; it never captures or decrypts a backup.
            return super().submit_transport(request)

        def status(self):
            result = super().status()
            ready = True
            try:
                check_storage(state, record)
            except (InstallError, OSError, ValueError):
                ready = False
            result['managed_service'] = {'managed': True, 'storage_ready': ready,
                                         'custody': record['storage_layout'],
                                         'off_host_protection': 'not-proven'}
            return result

    lifecycle_worker.Worker = ManagedWorker
    notification_done = threading.Event()

    def notify():
        try:
            # Host recovery must remain usable after mTLS certificate expiry.
            # Full mTLS readiness is checked during setup and shown separately.
            wait_ready(state, record, timeout=80, network=False)
            address = os.environ.get('NOTIFY_SOCKET')
            if address:
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as connection:
                    connection.connect('\0' + address[1:] if address.startswith('@') else address)
                    connection.sendall(b'READY=1\nSTATUS=IRIS lifecycle Unix endpoint ready')
        except (InstallError, OSError, ValueError):
            pass
        finally:
            notification_done.set()

    notifier = threading.Thread(target=notify, daemon=True)
    notifier.start()
    worker_args = SimpleNamespace(state_dir=state,
        backup_dir=Path(record['storage']['backup']['directory']),
        recovery_dir=Path(record['storage']['recovery']['directory']),
        recovery_identity=Path(record['recovery_identity']) if record['recovery_identity'] else None,
        extract_dir=state / 'isolated-restores', listen_address=record['listen_address'])
    try:
        return lifecycle_worker.serve(worker_args)
    finally:
        lifecycle_worker.Worker = original
