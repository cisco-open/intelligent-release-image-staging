# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Explicit host image custody for Docker installs, backups and restores."""

import copy
import json
import os
from pathlib import Path
import re
import stat

from .state import InstallError, Journal, atomic_write, regular_bytes


def validate_name(value):
    if (not isinstance(value, str) or not re.fullmatch(r'/[A-Za-z0-9_./-]+', value)
            or str(Path(value)) != value or '..' in Path(value).parts
            or len(Path(value).parts) < 3):
        raise InstallError('Choose a dedicated absolute image folder, such as /opt/images')
    for reserved in ('/etc', '/proc', '/sys', '/dev', '/run', '/root', '/usr', '/boot',
                     '/bin', '/sbin', '/lib', '/lib64', '/var/lib/docker', '/var/lib/containerd'):
        if overlaps(Path(value), Path(reserved)):
            raise InstallError('Choose a dedicated image folder outside system storage')


def overlaps(first, second):
    return first == second or first in second.parents or second in first.parents


def image_root(installation):
    value = installation.config.get('image_root')
    if value is None:
        return installation.base / 'images'
    validate_name(value)
    root = Path(value)
    if overlaps(root, installation.base):
        raise InstallError('The external image folder must be separate from installer state')
    recovering = getattr(installation, 'restore_operation_id', None) is not None
    if root.resolve() != root or (not root.is_dir() and not (recovering and not root.exists())) or root.is_mount():
        raise InstallError('Choose an existing image directory without symlinks; use a folder inside a mounted disk')
    # Restore publishes a sibling directory by rename. A mount below this tree
    # cannot be captured/replaced as ordinary deployment storage.
    for parent, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            child = Path(parent) / name
            if child.is_symlink() or child.is_mount():
                raise InstallError('Image folders must not contain links or nested mounts')
            info = child.lstat()
            if (not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                    or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
                raise InstallError('Image folders must contain ordinary files and directories only')
    return root


def require_approval(args):
    if os.geteuid() != 0 or not args.allow_downtime:
        raise InstallError('Run with sudo and --allow-downtime; the server restarts briefly')


def finish(intent):
    from .restore_storage import sync
    intent.unlink()
    sync(intent.parent)


def check_readable(adapter, root):
    compose = json.loads(regular_bytes(adapter.compose_file))
    image = adapter.journal.document['completed']['images'][compose['services']['iris']['image']]
    code = ('import os\n'
            'def fail(error):\n raise error\n'
            'for parent, dirs, files in os.walk("/images", onerror=fail):\n'
            ' for name in files:\n'
            '  with open(os.path.join(parent,name), "rb") as stream: stream.read(1)\n')
    try:
        adapter.command(['docker', 'run', '--rm', '--network', 'none', '--read-only',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', '10001:10001',
            '--mount', 'type=bind,source=' + str(root) + ',target=/images,readonly',
            '--entrypoint', 'python3', image, '-B', '-c', code], capture=True, timeout=60)
    except InstallError:
        raise InstallError('The image folder must be readable by container user 10001; no permissions were changed') from None


def change(args):
    """Switch an empty import root, with a durable same-command rollback intent."""
    from .backup import capture_plan
    from .deploy import DockerInstall
    require_approval(args)
    validate_name(str(args.path))
    with Journal(args.state_dir).locked() as journal:
        if journal.document is None or journal.document['config']['target'] != 'docker':
            raise InstallError('Changing an existing image folder requires a one-host Docker installation')
        intent = journal.directory / 'image-root-change.json'
        if intent.exists() or intent.is_symlink():
            saved = json.loads(regular_bytes(intent, 8 * 1024 * 1024))
            if saved['path'] != str(args.path) or saved['journal']['id'] != journal.document['id']:
                raise InstallError('Rerun the original image-root command to recover its interrupted change')
            # Do not adopt unrelated edits during interrupted recovery.
            if (journal.document not in (saved['journal'], saved['new_journal']) or
                    json.loads(regular_bytes(journal.directory / 'compose.json')) not in
                    (saved['compose'], saved['new_compose'])):
                raise InstallError('Image-folder recovery found changed deployment records')
            atomic_write(journal.directory / 'compose.json', saved['compose_bytes'].encode())
            journal.document = saved['journal']
            journal.save()
            DockerInstall(journal).compose('up', '-d', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '180')
            finish(intent)
        adapter = DockerInstall(journal)
        capture_plan(adapter)
        jobs_path = journal.directory / 'lifecycle-jobs.json'
        jobs = json.loads(regular_bytes(jobs_path)) if jobs_path.exists() else []
        if any(j.get('state') in ('running', 'queued', 'recovery-required') for j in jobs):
            raise InstallError('Finish or recover maintenance work before changing the image folder')
        previous = image_root(adapter)
        if previous == args.path:
            print('This image folder is already connected.')
            return 0
        if any(previous.iterdir()):
            raise InstallError('The current import folder must be empty; existing images will not be hidden or moved')
        updated = copy.deepcopy(journal.document)
        updated['config']['image_root'] = str(args.path)
        candidate = copy.copy(adapter)
        candidate.config = updated['config']
        image_root(candidate)
        check_readable(adapter, args.path)
        old_bytes = regular_bytes(adapter.compose_file).decode()
        original = json.loads(old_bytes)
        replacement = copy.deepcopy(original)
        mounts = [m for m in replacement['services']['iris']['volumes'] if m.get('target') == '/opt/images']
        if len(mounts) != 1 or mounts[0].get('source') != str(previous) or mounts[0].get('read_only') is not True:
            raise InstallError('The recorded image mount does not match this installation')
        mounts[0]['source'] = str(args.path)
        new_bytes = json.dumps(replacement, sort_keys=True, indent=2).encode()
        import hashlib
        updated['completed']['prepared'] = hashlib.sha256(new_bytes).hexdigest()
        saved = dict(path=str(args.path), journal=journal.document, new_journal=updated,
                     compose=original, new_compose=replacement, compose_bytes=old_bytes)
        atomic_write(intent, json.dumps(saved, sort_keys=True).encode())
        try:
            adapter.compose('stop', 'console', 'iris')
            atomic_write(adapter.compose_file, new_bytes)
            journal.document = updated
            journal.save()
            candidate = DockerInstall(journal)
            candidate.prepare()
            candidate.compose('up', '-d', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '180')
            # Admission must work against actual new mounts before committing.
            from .backup import docker_capture_plan
            docker_capture_plan(candidate)
        except BaseException:
            atomic_write(adapter.compose_file, old_bytes.encode())
            journal.document = saved['journal']
            journal.save()
            adapter.compose('up', '-d', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '180')
            finish(intent)
            raise
        finish(intent)
        print('Image folder connected read-only. Upload storage is unchanged. Backups include both folders.')
        return 0
