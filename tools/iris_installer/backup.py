# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Cold backups of installer-owned Docker and Kubernetes deployments.

The two encrypted sets preserve data and the service identity separately.
The restore module admits explicit same-deployment recovery only after current
security authority is verified. Capture alone never authorizes fleet cutover.
Topology adapters resolve owned storage and prove stopped writers before capture.
"""

from contextlib import contextmanager
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


def capture_plan(installation, *, allow_missing_prebuilt=False, cleanup_on_failure=False):
    from .backup_capture import guard as capture_guard
    capture_guard(installation.base, request_id=getattr(installation, 'backup_capture_id', None),
                  instance_id=installation.journal.document['id'])
    from .restore import guard
    guard(installation.base, operation_id=getattr(installation, 'restore_operation_id', None),
          upgrade_operation_id=getattr(installation, 'application_upgrade_id', None))
    hook = getattr(installation, 'capture_plan', None)
    sources, volumes, containers = hook() if hook is not None else docker_capture_plan(installation)
    from .prebuilt_backup import capture_sources
    try:
        caches = capture_sources(installation, allow_missing=allow_missing_prebuilt)
        if set(caches) & sources.keys():
            raise InstallError('Backup cache component conflicts with the deployment topology')
        sources.update(caches)
    except BaseException:
        # Only standalone capture owns disposable mirrors here. Restore and
        # credential transactions can retain these paths for explicit recovery.
        cleanup = getattr(installation, 'cleanup_snapshot_sources', None)
        if cleanup_on_failure and cleanup is not None:
            cleanup(sources)
        raise
    return sources, volumes, containers


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
    from .image_storage import image_root, overlaps
    sources['images'] = image_root(installation)
    external_images = installation.config.get('image_root') is not None
    if external_images:
        mounts = [m for m in compose['services']['iris'].get('volumes', []) if m.get('target') == '/opt/images']
        if (len(mounts) != 1 or mounts[0].get('type') != 'bind' or
                mounts[0].get('source') != str(sources['images']) or mounts[0].get('read_only') is not True):
            raise InstallError('External image mount differs from the recorded read-only folder')
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
        if external_images and overlaps(sources['images'], sources[member]):
            raise InstallError('External images must not overlap Docker volume storage')
        volumes[name] = str(sources[member])
    containers = []
    for service in services:
        record, = json.loads(installation.command(
            ['docker', 'container', 'inspect', compose['services'][service]['container_name']], capture=True))
        if (record['Config'].get('Labels', {}).get('com.cisco.iris.installer') != journal.document['id']
                or record['Image'] != completed['images'][compose['services'][service]['image']]):
            raise InstallError("Deployment container identity changed")
        if external_images and service == 'iris':
            roots = [m for m in record['Mounts'] if m.get('Destination') == '/opt/images']
            if (len(roots) != 1 or roots[0].get('Type') != 'bind' or
                    roots[0].get('Source') != str(sources['images']) or roots[0].get('RW') is not False):
                raise InstallError('Running image mount differs from the recorded read-only folder')
        for mount in record['Mounts']:
            if (external_images and service == 'iris' and mount.get('Destination') == '/opt/images'
                    and mount['Type'] == 'bind' and mount['Source'] == str(sources['images'])
                    and mount.get('RW') is False):
                continue
            if mount['Type'] == 'volume' and mount.get('Name') not in volumes:
                raise InstallError("Container uses an unaccounted volume")
            if mount['Type'] == 'bind' and mount['Source'] not in {
                    str(installation.base / name) for name in ('images', 'artifacts', 'age.txt', 'control')
                    } | {'/dev/null'}:
                raise InstallError("Container uses an unaccounted host path")
        containers.append({'id': record['Id'], 'service': service, 'running': record['State']['Running']})
    ids = installation.command(['docker', 'container', 'ls', '-aq'], capture=True).decode().split()
    owned = {record['id'] for record in containers}
    storage = [Path(path) for path in volumes.values()] + [sources['images'], sources['artifacts']]
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


@contextmanager
def _capture_workspace(installation):
    """Release this capture's temporary mirrors on success or refusal.

    Kubernetes plans allocate private snapshot directories before the capacity
    check. These are capture inputs, not live data or recovery authority.
    Leave operation records and any published encrypted archives intact.
    """
    sources, volumes, containers = capture_plan(installation, cleanup_on_failure=True)
    try:
        yield sources, volumes, containers
    finally:
        cleanup = getattr(installation, 'cleanup_snapshot_sources', None)
        if cleanup is not None:
            cleanup(sources)


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
        installation.application_upgrade_id = getattr(args, 'application_upgrade_id', None)
        if getattr(args, 'managed_capture', False) is True:
            installation.backup_capture_id = args.request_id
        with _capture_workspace(installation) as (sources, volumes, containers):
            capacity_preflight(installation, sources, output, recovery)
            signer = initialize(journal, installation)
            recipient = journal.document['config']['recovery_recipient']
            set_id = str(uuid.uuid4())
            metadata = {'backup_set_id': set_id, 'instance_id': journal.document['id'],
                        'target': target_name(installation), 'volumes': volumes,
                        'image_ids': journal.document['completed']['images'],
                        'scope': 'managed-deployment-files', 'cutover_permitted': False}
            capture = None
            if getattr(args, 'managed_capture', False) is True:
                from .backup_capture import Capture
                capture = Capture(installation, args.request_id, args.backup_id).begin(
                    output=output, recovery=recovery, signer=signer, containers=containers,
                    volumes=volumes, set_id=set_id)
                callback = getattr(args, 'on_capture_started', None)
                if callback is not None:
                    callback()
            # Export immutable service images while the deployment is still running.
            with tempfile.TemporaryDirectory(prefix='backup-images-', dir=journal.directory) as temporary:
                images = Path(temporary) / 'images.tar'
                if capture:
                    capture.phase('exporting')
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
                    if capture:
                        capture.phase('stopping')
                    stop_writers(installation, containers)
                    if capture:
                        capture.record['clean_stop'] = True
                        capture.phase('capturing')
                    extras = getattr(installation, 'capture_backup_extras', None)
                    if extras is not None:
                        extras(sources)
                    receipt = backup_archive.create({'service-identity': installation.base / 'age.txt',
                                           'backup-signer': signer}, recovery, recipient, signer,
                        metadata=dict(metadata, scope='identity-recovery'),
                        **({'on_stage': lambda path: capture.stage('recovery', path)} if capture else {}))
                    if capture:
                        capture.published('recovery', receipt)
                    receipt = backup_archive.create(sources, output, recipient, signer, metadata=metadata,
                        **({'on_stage': lambda path: capture.stage('data', path)} if capture else {}))
                    if capture:
                        capture.published('data', receipt)
                    status['state'] = 'captured'
                except Exception:
                    status['state'] = 'failed'
                    raise
                finally:
                    if capture:
                        capture.phase('restarting')
                    # Original services only, in server-then-Console order. Capturing
                    # never changes live bytes, so restart is safe even after failure.
                    for container in reversed(containers):
                        if container['running']:
                            try:
                                restart_writer(installation, container)
                                if capture:
                                    capture.record['restarted'].append(container['service'])
                                    capture.save()
                            except (InstallError, OSError):
                                restart_errors.append(container['service'])
                    status['restart_required'] = restart_errors
                    status['finished_at'] = int(time.time())
                    atomic_write(status_path, json.dumps(status).encode())
                    if capture:
                        capture.record['restart_required'] = restart_errors
                        capture.phase('settled-' + status['state'] if not restart_errors else 'restarting')
                if restart_errors:
                    raise InstallError("Backup captured, but service restart needs attention")
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


def recover(state_dir, *, request_id, backup_id, pre_authority_recovery=False):
    """Settle only the exact managed capture; never call create() again."""
    from .backup_capture import Capture, guard as capture_guard, writer_authority, _private
    from .upgrade_state import guard as upgrade_guard
    upgrade_guard(state_dir)
    with Journal(state_dir).locked() as journal:
        if journal.document is None:
            raise InstallError('No managed deployment was found')
        installation = _installation(journal)
        capture_guard(state_dir, request_id=request_id, instance_id=journal.document['id'])
        operation = Capture(installation, request_id, backup_id)
        try:
            operation.load()
        except FileNotFoundError:
            if pre_authority_recovery is not True:
                raise InstallError('This capture has no saved same-job recovery authority. Preserve the original evidence; no services were restarted.') from None
            jobs = json.loads(_private(Path(state_dir) / 'lifecycle-jobs.json'))
            selected = [job for job in jobs if job.get('id') == request_id]
            if (len(selected) != 1 or selected[0].get('action') != 'backup'
                    or selected[0].get('backup_id') != backup_id
                    or selected[0].get('capture_authority_started') is not False
                    or selected[0].get('state') not in ('running', 'recovery-required')):
                raise InstallError('Capture preflight recovery does not match the saved same-job handoff')
            # The worker persisted this exact FALSE marker before dispatch,
            # and intent publication precedes every exporter/stop command.
            # No intent + FALSE therefore admits NO restart or recapture.
            # Still prove actual worker/writer quiescence before unblocking.
            writer_authority(installation)
            return {'state': 'failed', 'services_healthy': False, 'recaptured': False,
                    'partial_output_retained': True, 'preflight_only': True}
        return operation.settle()
