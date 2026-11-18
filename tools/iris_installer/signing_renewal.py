# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Host-owned automatic renewal of one explicitly bound online signing key.

Root private keys stay with their existing owner, outside deployment storage.
Only public requests and certificates enter the server. Changed signing/root
identities require a new explicit enrollment; the timer never adopts them.
"""

import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import time
import uuid

from .state import InstallError, Journal, atomic_write, regular_bytes

RECORD = 'signing-renewal.json'
RUNTIME = Path('/var/lib/iris-signing-renewal')
UNITS = Path('/etc/systemd/system')
ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'}


def cycle(record, snapshot, sign, apply, save, *, now):
    """Retry only a guarded approval, reconciling lost import acknowledgments."""
    current = snapshot()
    request = current['request']
    roots = {normalize_public(value) for value in current['roots'].values()}
    if (request['public_key_sha256'] != record['public_key_sha256']
            or record['root_public'] not in roots):
        record['state'] = 'review-required'
        save(record)
        raise InstallError('Signing identity changed. Review and enable renewal again for this identity')
    if now < record.get('checked_at', 0):
        raise InstallError('Server clock moved backwards; check time before renewal')
    record.update(checked_at=now, renew_at=current['renew_at'],
                  expires_at=current['expires_at'], refuse_at=current['refuse_at'])
    pending = record.get('pending')
    reconciled = False
    if pending:
        approved = hashlib.sha256(pending['certificate'].encode('ascii')).hexdigest()
        if request['certificate_sha256'] == approved:
            record.update(pending=None, pending_created_at=None, state='renewed', last_success_at=now)
            save(record)
            pending = None
            reconciled = True
        elif (request['certificate_sha256'] != pending['certificate_sha256']
              or now - record['pending_created_at'] >= 22 * 86400):
            # Another successful renewal wins; an old approval is never replayed.
            # An unimported approval also ages out before its own cutoff.
            record['pending'] = None
            record['pending_created_at'] = None
            pending = None
            save(record)
    if not pending and now < current['renew_at']:
        record['state'] = 'renewed' if reconciled else 'waiting'
        save(record)
        return record
    if not pending:
        certificate = sign(request['public_key'])
        pending = {key: request[key] for key in ('public_key_sha256', 'certificate_sha256')}
        pending['certificate'] = certificate
        record.update(pending=pending, pending_created_at=now, state='renewing')
        save(record)  # Durable public approval precedes the guarded server import.
    result = apply(pending)
    if result.get('applied') is not True:
        raise InstallError('Renewal result is uncertain; the next check will reconcile it')
    after = snapshot()
    if (after['request']['public_key_sha256'] != record['public_key_sha256']
            or after['request']['certificate_sha256'] != hashlib.sha256(pending['certificate'].encode('ascii')).hexdigest()
            or after['refuse_at'] <= now):
        raise InstallError('Renewal needs verification; the next check will reconcile it')
    record.update(pending=None, pending_created_at=None, state='renewed', last_success_at=now,
                  renew_at=after['renew_at'], expires_at=after['expires_at'], refuse_at=after['refuse_at'])
    save(record)
    return record


def normalize_public(value):
    from .key_setup import public_key
    return public_key(value.encode('ascii') if isinstance(value, str) else value).decode('ascii')


def public_status(record):
    return {'schema': 1, 'enabled': record['enabled'], 'state': record['state'],
            **{name: record.get(name) for name in
               ('checked_at', 'renew_at', 'expires_at', 'refuse_at', 'last_success_at')}}


def server(install, action, payload=None):
    code = {'snapshot': 'print(json.dumps(s.snapshot()))',
            'status': 'print(json.dumps(s.readiness()))',
            'publish': 's.publish_status(json.load(sys.stdin));print("{}")',
            'renew': 'import certificate_lifecycle as c;print(json.dumps(c.renew(json.load(sys.stdin))))'}[action]
    raw = install.execute('python3', '-I', '-B', '-c',
                          'import sys,json;sys.path.insert(0,"/opt/iris/server");import signing_renewal as s;' + code,
                          input=json.dumps(payload).encode(), capture=True, timeout=90)
    return json.loads(raw)


def holder(record, request=None):
    """Run the pinned public-only signing helper as the existing root owner."""
    code = '''import sys,json,tempfile,pathlib
sys.path.insert(0,sys.argv[1])
from iris_installer import automatic_keys
d=json.load(sys.stdin);root=pathlib.Path(d['root'])
public=automatic_keys.root_public(root).decode('ascii')
if d.get('expected') is not None and public!=d['expected']: raise ValueError('Root changed')
if d.get('request') is None: print(json.dumps({'public':public}))
else:
 with tempfile.TemporaryDirectory(prefix='iris-renewal-') as directory:
  p=pathlib.Path(directory)/'online.pub';p.write_text(d['request'])
  out=pathlib.Path(directory)/'online-cert.pub'
  automatic_keys.sign_online(root,p,out)
  print(json.dumps({'certificate':out.read_text()}))
'''
    owner = pwd.getpwuid(record['holder_uid'])
    if os.geteuid() not in (0, owner.pw_uid):
        raise InstallError('Run renewal as the managed key owner or through its enrolled host service')
    identity = {'user': owner.pw_uid, 'group': owner.pw_gid, 'extra_groups': []} if os.geteuid() == 0 else {}
    try:
        result = subprocess.run(['/usr/bin/python3', '-I', '-B', '-c', code, record['runtime']],
                                input=json.dumps({'root': record['root_key'], 'expected': record.get('root_public'), 'request': request}).encode(),
                                **identity,
                                env=ENV, capture_output=True, timeout=90, check=False)
        if result.returncode:
            raise InstallError('Managed signing key unavailable; check its owner and protected key folder')
        return json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        raise InstallError('Managed signing key unavailable; existing keys were kept') from None


def checked_record(state, identifier):
    p = state / RECORD
    info = p.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise InstallError('Unsafe renewal enrollment; preserve it for investigation')
    record = json.loads(regular_bytes(p, 128 * 1024))
    required = {'schema', 'instance_id', 'state_dir', 'root_key', 'holder_uid', 'runtime',
                'enabled', 'state', 'public_key_sha256', 'root_public', 'pending',
                'checked_at', 'last_success_at', 'renew_at', 'expires_at', 'refuse_at', 'pending_created_at'}
    if (not isinstance(record, dict) or set(record) != required
            or type(record['schema']) is not int or record['schema'] != 1 or record['instance_id'] != identifier
            or record['state_dir'] != str(state) or type(record['enabled']) is not bool
            or type(record['holder_uid']) is not int or record['holder_uid'] < 0
            or record['state'] not in ('disabled', 'waiting', 'renewing', 'renewed', 'error', 'review-required')
            or not isinstance(record['public_key_sha256'], str) or not re.fullmatch('[a-f0-9]{64}', record['public_key_sha256'])
            or not isinstance(record['root_public'], str)
            or any(record[name] is not None and (type(record[name]) is not int or record[name] < 0)
                   for name in ('checked_at', 'last_success_at', 'renew_at', 'expires_at', 'refuse_at', 'pending_created_at'))
            or type(record['checked_at']) is not int):
        raise InstallError('Renewal enrollment does not match this installation')
    for name in ('root_key', 'runtime'):
        if not isinstance(record[name], str) or not Path(record[name]).is_absolute():
            raise InstallError('Invalid renewal path')
    runtime = Path(record['runtime'])
    if runtime.parent != RUNTIME / identifier or not re.fullmatch('[a-f0-9]{64}', runtime.name):
        raise InstallError('Renewal runtime does not match its enrollment')
    if normalize_public(record['root_public']) != record['root_public']:
        raise InstallError('Invalid enrolled public root')
    pending = record['pending']
    if pending is not None and (not isinstance(pending, dict)
            or set(pending) != {'certificate', 'public_key_sha256', 'certificate_sha256'}
            or not isinstance(pending['certificate'], str) or len(pending['certificate']) > 65536
            or any(not isinstance(pending[name], str) or not re.fullmatch('[a-f0-9]{64}', pending[name])
                   for name in ('public_key_sha256', 'certificate_sha256'))
            or pending['public_key_sha256'] != record['public_key_sha256']):
        raise InstallError('Pending renewal approval is invalid; preserve it for review')
    if (pending is None) != (record['pending_created_at'] is None):
        raise InstallError('Pending approval has no matching timestamp')
    return record


def install_runtime(identifier):
    """Readable source only; no keys, passphrases, or deployment data copied."""
    from .managed_worker import _path
    source = Path(__file__).resolve().parent
    files = {p.name: p.read_bytes() for p in source.glob('*.py')}
    digest = hashlib.sha256(b''.join(name.encode() + files[name] for name in sorted(files))).hexdigest()
    root = RUNTIME / identifier / digest
    for path in (RUNTIME, RUNTIME / identifier, root, root / 'iris_installer'):
        _path(path)
        path.mkdir(mode=0o755, exist_ok=True)
    for name, content in files.items():
        p = root / 'iris_installer' / name
        if p.exists() or p.is_symlink():
            if p.is_symlink() or p.stat().st_uid != 0 or p.stat().st_mode & 0o022 or regular_bytes(p) != content:
                raise InstallError('Pinned renewal runtime changed')
        else:
            atomic_write(p, content, mode=0o755 if name == 'automatic_askpass.py' else 0o644)
    launcher = b'import sys\nfrom pathlib import Path\nsys.path.insert(0,str(Path(__file__).resolve().parent))\nfrom iris_installer.signing_renewal import main\nraise SystemExit(main())\n'
    p = root / 'launch.py'
    if p.exists() and regular_bytes(p) != launcher:
        raise InstallError('Renewal launcher changed')
    if not p.exists():
        atomic_write(p, launcher, mode=0o644)
    return str(root)


def unit_files(record):
    from .managed_worker import _quote
    name = 'iris-signing-renewal-' + record['instance_id']
    service = ('[Unit]\nDescription=IRIS signing certificate renewal\nAfter=docker.service network-online.target\n'
               '[Service]\nType=oneshot\nUser=root\nUMask=0077\nTimeoutStartSec=300\nRestart=on-failure\nRestartSec=1h\n'
               'ExecStart=/usr/bin/python3 -I -B ' + _quote(Path(record['runtime']) / 'launch.py')
               + ' run --state-dir ' + _quote(record['state_dir']) + '\n')
    timer = ('[Unit]\nDescription=Check IRIS signing certificate renewal\n[Timer]\n'
             'OnBootSec=2min\nOnCalendar=*-*-* 03:00:00 UTC\nPersistent=true\nRandomizedDelaySec=15min\n'
             'Unit=' + name + '.service\n[Install]\nWantedBy=timers.target\n')
    return {name + '.service': service.encode(), name + '.timer': timer.encode()}


def operate(args):
    from .deploy import installation
    from .managed_worker import _root, command, _file
    _root()
    with Journal(args.state_dir).locked() as journal:
        if journal.document is None:
            raise InstallError('Choose an existing managed installation')
        install = installation(journal)
        install.verify_resource_ownership()
        state, identifier = journal.directory, journal.document['id']
        if str(uuid.UUID(identifier)) != identifier:
            raise InstallError('Installation identity is invalid')
        save = lambda record: atomic_write(state / RECORD, (json.dumps(record, sort_keys=True) + '\n').encode())
        if args.action == 'enable':
            root = Path(args.root_key).absolute()
            if root.resolve() != root or not root.is_file():
                raise InstallError('Choose an existing managed root without symbolic links')
            for excluded in (state, install.source, Path('/opt/images'), Path('/opt/iris'),
                             Path('/etc/iris'), Path(install.config.get('image_root') or '/opt/images')):
                if root == excluded or excluded in root.parents:
                    raise InstallError('Signing roots must remain outside deployment, source, and image folders')
            current = server(install, 'snapshot')
            record = {'schema': 1, 'instance_id': identifier, 'state_dir': str(state),
                      'root_key': str(root), 'holder_uid': root.stat().st_uid,
                      'runtime': install_runtime(identifier), 'enabled': True, 'state': 'waiting',
                      'public_key_sha256': current['request']['public_key_sha256'], 'pending': None, 'pending_created_at': None,
                      'checked_at': int(time.time()), 'last_success_at': None,
                      **{key: current[key] for key in ('renew_at', 'expires_at', 'refuse_at')}}
            record['root_public'] = normalize_public(holder(record)['public'])
            if record['root_public'] not in {normalize_public(x) for x in current['roots'].values()}:
                raise InstallError('Managed root does not match this installation')
            previous = None
            if (state / RECORD).exists():
                previous = checked_record(state, identifier)
                # Same enrollment preserves pending approvals and success history.
                if all(previous[key] == record[key] for key in ('root_key', 'holder_uid', 'root_public', 'public_key_sha256')):
                    record.update({key: previous.get(key) for key in ('pending', 'pending_created_at', 'last_success_at')})
            files = unit_files(record)
            for name, data in files.items():
                destination = UNITS / name
                allowed = {data}
                if previous is not None:
                    allowed.add(unit_files(previous)[name])
                if (destination.exists() or destination.is_symlink()) and _file(destination, mode=0o644) not in allowed:
                    raise InstallError('Existing renewal unit differs; preserve it for review')
                atomic_write(destination, data, mode=0o644)
            save(record)
            command(['systemctl', 'daemon-reload'])
            command(['systemctl', 'enable', '--now', 'iris-signing-renewal-' + identifier + '.timer'])
        else:
            record = checked_record(state, identifier)
        if args.action == 'disable':
            record.update(enabled=False, state='disabled', checked_at=int(time.time()))
            save(record)
            command(['systemctl', 'disable', '--now', 'iris-signing-renewal-' + identifier + '.timer'])
        if args.action in ('run', 'enable') and record['enabled']:
            try:
                cycle(record, lambda: server(install, 'snapshot'),
                      lambda request: holder(record, request)['certificate'],
                      lambda payload: server(install, 'renew', payload), save, now=int(time.time()))
            except (InstallError, OSError, ValueError):
                if record['state'] != 'review-required':
                    record['state'] = 'error'
                record['checked_at'] = max(record.get('checked_at', 0), int(time.time()))
                save(record)
                try:
                    server(install, 'publish', public_status(record))
                except (InstallError, OSError, ValueError):
                    pass
                raise
        if args.action != 'status':
            server(install, 'publish', public_status(record))
        return dict(public_status(record), readiness=server(install, 'status'))


def add_arguments(parser):
    parser.add_argument('action', choices=('enable', 'disable', 'run', 'status'))
    parser.add_argument('--state-dir', type=Path, required=True)
    parser.add_argument('--root-key', type=Path)


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description='Automatic renewal for existing locally managed signing keys')
    add_arguments(parser)
    args = parser.parse_args(argv)
    if args.action == 'enable' and args.root_key is None:
        parser.error('enable requires --root-key')
    try:
        print(json.dumps(operate(args), sort_keys=True))
        return 0
    except (InstallError, OSError, ValueError):
        print('Signing renewal needs attention. Check the managed key folder, deployment, and renewal status.', file=sys.stderr)
        return 1
