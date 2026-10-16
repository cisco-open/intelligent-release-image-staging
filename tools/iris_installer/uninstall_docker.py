# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Exact-ID Docker removal, also executed over the pinned split-host transport.

This stdlib-only program accepts no shell command, pathname deletion or image
removal. Its caller durably records each intent before asking for a mutation.
"""

import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

LOCK = None


def require(value):
    if not value:
        raise ValueError('Uninstall resource identity or ownership changed')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def network_definition(row):
    """Keep configuration pinned, excluding only known live IP usage counts."""
    result = copy.deepcopy({key: value for key, value in row.items() if key != 'Containers'})
    status = result.get('Status')
    if status is not None:
        require(isinstance(status, dict))
        ipam = status.get('IPAM')
        if ipam is not None:
            require(isinstance(ipam, dict))
            subnets = ipam.get('Subnets')
            if subnets is not None:
                require(isinstance(subnets, dict) and len(subnets) <= 64)
                for subnet, values in subnets.items():
                    require(isinstance(subnet, str) and 0 < len(subnet) <= 128 and isinstance(values, dict))
                    for key in ('IPsInUse', 'DynamicIPsAvailable'):
                        if key in values:
                            require(type(values[key]) is int and 0 <= values[key] <= 2**128)
                            del values[key]
    return result


def command(argv):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                            timeout=180, check=False, env={'PATH': '/usr/bin:/bin'},
                            pass_fds=(LOCK,) if LOCK is not None else ())
    require(result.returncode == 0)
    return result.stdout


def inventory(request, run):
    project, identity = request['project'], request['instance_id']
    require(isinstance(project, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,47}', project))
    require(isinstance(identity, str) and re.fullmatch(r'[0-9a-f-]{36}', identity))
    expected = request['names']
    require(set(expected) == {'container', 'volume', 'network'})
    resources = {}
    for kind in expected:
        ids = run(['docker', kind, 'ls', '-q', *(['-a'] if kind == 'container' else []),
                   '--filter', 'label=com.docker.compose.project=' + project]).decode().split()
        require(len(ids) <= 64)
        for identifier in ids:
            row, = json.loads(run(['docker', kind, 'inspect', identifier]))
            labels = row.get('Config', {}).get('Labels', {}) if kind == 'container' else row.get('Labels', {})
            require(labels.get('com.cisco.iris.installer') == identity
                    and labels.get('com.docker.compose.project') == project)
            name = row['Name'].lstrip('/')
            require(name in expected[kind])
            key = kind + '/' + name
            require(key not in resources)
            if kind == 'container':
                spec = expected[kind][name]
                require(row['Image'] == spec['image'] and labels.get('com.docker.compose.service') == spec['service'])
                host = copy.deepcopy(row['HostConfig'])
                restart = host.pop('RestartPolicy', {})
                pinned = {'config': row['Config'], 'host': host, 'mounts': row['Mounts']}
                value = {'running': bool(row['State']['Running']), 'restart': restart,
                         'exit_code': row['State'].get('ExitCode'), 'oom': row['State'].get('OOMKilled', False)}
            elif kind == 'volume':
                require(row.get('Driver') == 'local' and not row.get('Options'))
                pinned = row
                value = {'mountpoint': row['Mountpoint']}
            else:
                pinned = network_definition(row)
                value = {'attached': sorted(row.get('Containers', {}))}
            resources[key] = {'id': row.get('Id', name), 'sha256': digest(pinned), **value}
    # Shared writers and existing network connections do not authorize removal.
    owned = {v['id'] for k, v in resources.items() if k.startswith('container/')}
    for key, value in resources.items():
        if key.startswith('network/'):
            require(set(value['attached']) <= owned)
    volume_names = set(expected['volume'])
    mountpoints = [Path(row['mountpoint']) for key, row in resources.items() if key.startswith('volume/')]
    for identifier in run(['docker', 'container', 'ls', '-aq']).decode().split():
        if any(identifier == item or item.startswith(identifier) for item in owned):
            continue
        row, = json.loads(run(['docker', 'container', 'inspect', identifier]))
        for mount in row.get('Mounts', []):
            source = Path(mount.get('Source', '/nonexistent-uninstall-mount'))
            # A read-only host monitor may mount an ancestor such as /. Direct
            # volume consumers and binds within the data remain removal blockers.
            require(mount.get('Name') not in volume_names and not (mount.get('Type') == 'bind' and any(
                source == path or path in source.parents or
                (source in path.parents and mount.get('RW') is not False) for path in mountpoints)))
    engine = json.loads(run(['docker', 'info', '--format', '{{json .ID}}']))
    require(isinstance(engine, str) and bool(engine))
    return {'engine': engine, 'resources': resources}


def stable(snapshot):
    return {'engine': snapshot['engine'], 'resources': {
        key: {name: row[name] for name in ('id', 'sha256')}
        for key, row in snapshot['resources'].items()}}


def perform(request, run=command):
    require(set(request) <= {'project', 'instance_id', 'names', 'root', 'action', 'expected', 'key'})
    current = inventory(request, run)
    action = request.get('action', 'inspect')
    if action == 'inspect':
        return current
    require(action in ('stop', 'remove') and stable(current) == request['expected'])
    key = request['key']
    require(key in current['resources'])
    kind, name = key.split('/', 1)
    row = current['resources'][key]
    if action == 'stop':
        require(kind == 'container')
        run(['docker', 'update', '--restart=no', row['id']])
        if row['running']:
            run(['docker', 'stop', '--time', '120', row['id']])
        after = inventory(request, run)
        require(stable(after) == stable(current))
        stopped = after['resources'][key]
        require(not stopped['running'] and not stopped['oom'] and stopped['exit_code'] in (0, 143)
                and stopped['restart'].get('Name') == 'no')
        return after
    require(all(not item['running'] for k, item in current['resources'].items() if k.startswith('container/')))
    # Exact identifiers; no force, recursive host deletion, Compose down or prune.
    run(['docker', kind, 'rm', row['id']])
    after = inventory(request, run)
    wanted = copy.deepcopy(request['expected'])
    del wanted['resources'][key]
    require(stable(after) == wanted)
    return after


def remote(request):
    """Same existing root-held Console owner marker and independent host lock."""
    global LOCK
    root = Path(request['root'])
    require(root.is_absolute() and len(root.parts) >= 3 and root.resolve() == root)
    for path in (root, *root.parents):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
    marker = root / 'owner.json'
    fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600)
        require(json.loads(stream.read(65537)) == {'instance_id': request['instance_id'], 'project': request['project']})
    fd = os.open(root / '.backup-capture.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        LOCK = fd
        return perform(request)
    finally:
        LOCK = None
        os.close(fd)


if __name__ == '__main__':
    try:
        raw = sys.stdin.buffer.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024)
        print(json.dumps(remote(json.loads(raw)), sort_keys=True))
    except Exception:
        print('Scoped remote uninstall stopped; preserve its operation.', file=sys.stderr)
        raise SystemExit(1) from None
