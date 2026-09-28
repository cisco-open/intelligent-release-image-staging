# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Cold backups of installer-owned Docker and Kubernetes deployments.

The two encrypted sets preserve data and the service identity separately. Restore
currently verifies/extracts isolated files; it never authorizes fleet cutover.
Topology adapters resolve owned storage and prove stopped writers before capture.
"""

import json
import itertools
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import time
import uuid

from . import backup_archive
from .deploy import DockerInstall, digest
from .state import InstallError, Journal, atomic_write, regular_bytes


def initialize(journal, installation):
    """Create a dedicated deployment BACKUP signer; never touch instruction roots."""
    directory = journal.directory / 'backup-custody'
    directory.mkdir(mode=0o700, exist_ok=True)
    backup_archive.private_directory(directory)
    key = directory / 'signer'
    if not key.exists() and not key.is_symlink():
        if any(directory.iterdir()):
            raise InstallError("Partial backup custody exists; do not regenerate it")
        installation.command(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C',
                              'iris-deployment-backup', '-f', key])
    info = key.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise InstallError("Unsafe backup signing identity")
    public = installation.command(['ssh-keygen', '-y', '-f', key], capture=True).strip() + b'\n'
    if not public.startswith(b'ssh-ed25519 '):
        raise InstallError("Unexpected backup signing identity")
    if (directory / 'signer.pub').exists():
        existing = regular_bytes(directory / 'signer.pub', 4096).split()[:2]
        if existing != public.split()[:2]:
            raise InstallError("Backup public identity does not match; do not replace it")
    else:
        atomic_write(directory / 'signer.pub', public, 0o644)
    return key


def capture_plan(installation):
    hook = getattr(installation, 'capture_plan', None)
    return hook() if hook is not None else docker_capture_plan(installation)


def docker_capture_plan(installation, *, services=('console', 'iris')):
    """Resolve exact existing resources. Refuse adoption or unaccounted mounts."""
    journal = installation.journal
    completed = journal.document['completed']
    if not all(name in completed for name in ('prepared', 'images', 'packages')):
        raise InstallError("Finish this installation before taking a deployment backup")
    installation.verify_inputs()
    installation.verify_resource_ownership()
    if digest(installation.compose_file) != completed['prepared']:
        raise InstallError("Deployment configuration changed; backup adoption is not supported")
    compose = json.loads(regular_bytes(installation.compose_file))
    if set(compose['services']) != set(services):
        raise InstallError("Deployment services differ from the owned topology")
    sources = {name: installation.base / name for name in ('source', 'roots', 'artifacts', 'images')}
    sources.update({'deployment': installation.compose_file,
                    'environment': installation.base / 'compose.env',
                    'installation': journal.path})
    volumes = {}
    for logical, spec in compose['volumes'].items():
        name = spec.get('name') or installation.config['instance'] + '_' + logical
        record, = json.loads(installation.command(['docker', 'volume', 'inspect', name], capture=True))
        if (record.get('Driver') != 'local' or record.get('Options')
                or record.get('Labels', {}).get('com.cisco.iris.installer') != journal.document['id']):
            raise InstallError("Backup requires owned local Docker volumes")
        member = 'volume-' + logical
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', member):
            raise InstallError("Unsupported volume name")
        sources[member] = Path(record['Mountpoint'])
        volumes[name] = str(sources[member])
    containers = []
    for service in services:
        record, = json.loads(installation.command(
            ['docker', 'container', 'inspect', compose['services'][service]['container_name']], capture=True))
        if (record['Config'].get('Labels', {}).get('com.cisco.iris.installer') != journal.document['id']
                or record['Image'] != completed['images'][compose['services'][service]['image']]):
            raise InstallError("Deployment container identity changed")
        for mount in record['Mounts']:
            if mount['Type'] == 'volume' and mount.get('Name') not in volumes:
                raise InstallError("Container uses an unaccounted volume")
            if mount['Type'] == 'bind' and mount['Source'] not in {
                    str(installation.base / name) for name in ('images', 'artifacts', 'age.txt', 'control')
                    } | {'/dev/null'}:
                raise InstallError("Container uses an unaccounted host path")
        containers.append({'id': record['Id'], 'service': service, 'running': record['State']['Running']})
    ids = installation.command(['docker', 'container', 'ls', '-aq'], capture=True).decode().split()
    owned = {record['id'] for record in containers}
    storage = [Path(path) for path in volumes.values()] + [installation.base / name for name in ('images', 'artifacts')]
    for identifier in ids:
        record, = json.loads(installation.command(['docker', 'container', 'inspect', identifier], capture=True))
        if record['Id'] in owned:
            continue
        for mount in record['Mounts']:
            if not mount.get('RW', True):
                continue
            source = Path(mount.get('Source', '/nonexistent-mount'))
            overlap = mount.get('Name') in volumes or (
                mount['Type'] == 'bind' and any(source == path or source in path.parents
                                               or path in source.parents for path in storage))
            if overlap:
                raise InstallError("Another container can write deployment storage; capture refused")
    return sources, volumes, containers


def capacity_preflight(installation, sources, output, recovery):
    """Reserve an estimate plus headroom BEFORE exporting images or stopping IRIS."""
    hook = getattr(installation, 'backup_capacity_preflight', None)
    if hook is not None:
        return hook(sources, output, recovery)
    size, count = 0, 0
    state_root = sources.get('volume-iris-state')
    live_control = Path(state_root) / 'iox/control.sock' if state_root is not None else None
    for source in sources.values():
        source = Path(source)
        paths = itertools.chain((source,), source.rglob('*') if source.is_dir() else ())
        for path in paths:
            info = path.lstat()
            count += 1
            if count > backup_archive.MAX_FILES:
                raise InstallError("Backup exceeds the supported file count")
            if stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    raise InstallError("Backup source contains hard-linked files")
                size += info.st_size
            elif (path == live_control and stat.S_ISSOCK(info.st_mode)
                  and info.st_uid == 10001 and stat.S_IMODE(info.st_mode) == 0o600):
                # The live IOx controller owns this ephemeral socket and removes
                # it during graceful shutdown. It has no payload to reserve.
                # Actual post-stop capture still rejects EVERY special file,
                # including this socket if shutdown failed to remove it.
                continue
            elif not stat.S_ISDIR(info.st_mode):
                raise InstallError("Backup source contains links or special files")
    image_bytes = 0
    for image_id in set(installation.journal.document['completed']['images'].values()):
        record, = json.loads(installation.command(['docker', 'image', 'inspect', image_id], capture=True))
        image_bytes += record['Size']
    # Different directories can share a filesystem; combine their reservations.
    reservations = {}
    for path, needed in ((installation.base, image_bytes),
                         (output.parent, size + image_bytes + count * 2048),
                         (recovery.parent, 1024 * 1024)):
        device = path.stat().st_dev
        previous = reservations.get(device, (path, 0))[1]
        reservations[device] = (path, previous + needed)
    for path, needed in reservations.values():
        if shutil.disk_usage(path).free < int(needed * 1.2) + 1024 ** 3:
            raise InstallError("Insufficient backup space including image export and one GiB of headroom")


def _installation(journal):
    if journal.document['config'].get('target', 'docker') == 'docker':
        return DockerInstall(journal)
    from .deploy import installation
    return installation(journal)


def target_name(installation):
    target = installation.config.get('target', 'docker')
    return {'docker': 'single-docker', 'docker-split': 'split-docker'}.get(target, target)


def stop_writers(installation, containers, *, recovering_clean_operation=False):
    hook = getattr(installation, 'stop_writers', None)
    if hook is not None:
        return hook(containers, recovering_clean_operation=recovering_clean_operation)
    for container in containers:
        record, = json.loads(installation.command(
            ['docker', 'container', 'inspect', container['id']], capture=True))
        if record['State']['Running']:
            installation.command(['docker', 'stop', '--time', '120', container['id']], timeout=180)
        record, = json.loads(installation.command(
            ['docker', 'container', 'inspect', container['id']], capture=True))
        state = record['State']
        if state['Running'] or (not recovering_clean_operation and (
                state.get('OOMKilled') or state.get('ExitCode') not in (0, 143))):
            raise InstallError('Maintenance requires cleanly stopped writers')


def restart_writer(installation, container):
    hook = getattr(installation, 'restart_writer', None)
    if hook is not None:
        return hook(container)
    installation.command(['docker', 'start', container['id']])
    deadline = time.monotonic() + 180
    while True:
        record, = json.loads(installation.command(
            ['docker', 'container', 'inspect', container['id']], capture=True))
        state = record['State']
        if not state['Running']:
            raise InstallError('Service exited after backup restart')
        if state.get('Health', {}).get('Status', 'healthy') == 'healthy':
            return
        if time.monotonic() >= deadline:
            raise InstallError('Service health did not recover after backup')
        time.sleep(1)


def create(args):
    if os.geteuid() != 0:
        raise InstallError("Run managed deployment backup with sudo")
    if not args.allow_downtime:
        raise InstallError("Backup stops IRIS briefly; review then pass --allow-downtime")
    output = Path(args.output).absolute()
    recovery = Path(args.recovery_output).absolute()
    backup_archive.private_directory(output.parent)
    backup_archive.private_directory(recovery.parent)
    if output == recovery or output.parent == recovery.parent:
        raise InstallError("Keep the identity recovery set in a separate protected directory")
    if any(path.exists() or path.is_symlink() for path in (output, recovery)):
        raise InstallError("Choose new backup and recovery destinations")
    with Journal(args.state_dir).locked() as journal:
        if journal.document is None:
            raise InstallError("No installer-owned deployment was found")
        installation = _installation(journal)
        sources, volumes, containers = capture_plan(installation)
        capacity_preflight(installation, sources, output, recovery)
        signer = initialize(journal, installation)
        recipient = journal.document['config']['recovery_recipient']
        set_id = str(uuid.uuid4())
        metadata = {'backup_set_id': set_id, 'instance_id': journal.document['id'],
                    'target': target_name(installation), 'volumes': volumes,
                    'image_ids': journal.document['completed']['images'],
                    'scope': 'managed-deployment-files', 'cutover_permitted': False}
        # Export immutable service images while the deployment is still running.
        with tempfile.TemporaryDirectory(prefix='backup-images-', dir=journal.directory) as temporary:
            images = Path(temporary) / 'images.tar'
            export = getattr(installation, 'backup_export_images', None)
            if export is not None:
                export(images)
            else:
                installation.command(['docker', 'image', 'save', '-o', images,
                                      *sorted(set(metadata['image_ids'].values()))])
            images.chmod(0o600)
            sources['container-images'] = images
            status = {'state': 'stopping', 'backup_set_id': set_id,
                      'started_at': int(time.time()), 'containers': containers}
            status_path = journal.directory / 'backup-operation.json'
            atomic_write(status_path, json.dumps(status).encode())
            restart_errors = []
            try:
                stop_writers(installation, containers)
                extras = getattr(installation, 'capture_backup_extras', None)
                if extras is not None:
                    extras(sources)
                backup_archive.create({'service-identity': installation.base / 'age.txt',
                                       'backup-signer': signer}, recovery, recipient, signer,
                                      metadata=dict(metadata, scope='identity-recovery'))
                backup_archive.create(sources, output, recipient, signer, metadata=metadata)
                status['state'] = 'captured'
            except Exception:
                status['state'] = 'failed'
                raise
            finally:
                # Original services only, in server-then-Console order. Capturing
                # never changes live bytes, so restart is safe even after failure.
                for container in reversed(containers):
                    if container['running']:
                        try:
                            restart_writer(installation, container)
                        except (InstallError, OSError):
                            restart_errors.append(container['service'])
                status['restart_required'] = restart_errors
                status['finished_at'] = int(time.time())
                atomic_write(status_path, json.dumps(status).encode())
            if restart_errors:
                raise InstallError("Backup captured, but service restart needs attention")
            cleanup = getattr(installation, 'cleanup_snapshot_sources', None)
            if cleanup is not None:
                cleanup(sources)
        print('Captured encrypted deployment and separate identity recovery sets: ' + set_id)
        print('Pin the backup signer public key outside this host: ' + str(signer) + '.pub')
        print('Capture is not a verified restore. Verify both sets using the independently held recovery identity.')
        return 0


def verify(args):
    report = backup_archive.read(args.backup, args.identity, args.trusted_signer,
                                 destination=getattr(args, 'destination', None),
                                 max_bytes=args.max_bytes)
    print(json.dumps(report, sort_keys=True))
    return 0
