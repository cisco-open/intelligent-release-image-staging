# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Import authenticated core images under installation-owned local tags only.

The caller supplies a verified release kit and records the returned evidence in
its protected journal. This module neither deploys services nor downloads images.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from .state import InstallError


ROLES = {'server-image': 'server', 'console-image': 'console'}
DIGEST = re.compile(r'sha256:[0-9a-f]{64}')


def _configuration(reference, expected, runner):
    # --raw is essential: hashing a pretty-printed representation would not
    # verify the config identity recorded by the authenticated release.
    data = runner(['skopeo', 'inspect', '--config', '--raw', reference],
                  capture=True, timeout=120)
    if (not isinstance(data, bytes) or not 1 <= len(data) <= 2 * 1024 * 1024
            or 'sha256:' + hashlib.sha256(data).hexdigest() != expected):
        raise InstallError('Prebuilt image configuration differs from the authenticated kit')
    try:
        document = json.loads(data)
    except (ValueError, UnicodeError):
        raise InstallError('Prebuilt image configuration is invalid') from None
    if (not isinstance(document, dict) or document.get('os') != 'linux'
            or document.get('architecture') != 'amd64'):
        raise InstallError('Prebuilt core images must target linux/amd64')


def _image_id(tag, runner):
    data = runner(['docker', 'image', 'inspect', tag, '--format', '{{.Id}}'],
                  capture=True, timeout=30)
    try:
        identity = data.decode('ascii').strip()
    except (AttributeError, UnicodeError):
        raise InstallError('Cannot establish imported image identity') from None
    if not DIGEST.fullmatch(identity):
        raise InstallError('Cannot establish imported image identity')
    return identity


def core_image_intent(kit, role, instance_id):
    """Public import identity for the caller to journal before host mutation."""
    if role not in ROLES or not isinstance(instance_id, str) or not re.fullmatch(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', instance_id):
        raise InstallError('Prebuilt image import needs a recorded installation identity and role')
    asset = kit.asset(role)
    if (asset.format != 'docker-archive' or asset.platforms != ('linux/amd64',)
            or not DIGEST.fullmatch(asset.config_digest)):
        raise InstallError('Invalid authenticated core image metadata')
    tag = 'iris-installer-prebuilt:' + instance_id + '-' + ROLES[role]
    return {'schema': 1, 'role': role, 'tag': tag,
            'config_digest': asset.config_digest, 'kit': kit.receipt()}


def import_core_image(kit, role, instance_id, workspace, runner, *, previous=None, intent=None):
    """Import one verified payload or verify an exact recorded prior import.

    Archive tags are never loaded into Docker: skopeo selects one explicitly
    generated local destination. An existing unrecorded destination is refused.
    A journaled intent permits recovery after import but before completion was
    recorded. The daemon image ID remains separate from the config digest.
    """
    evidence = core_image_intent(kit, role, instance_id)
    asset = kit.asset(role)
    tag = evidence['tag']
    if intent is not None and (previous is not None or intent != evidence):
        raise InstallError('Pending image import differs from the selected release or instance')
    if previous is not None:
        if (not isinstance(previous, dict) or set(previous) != set(evidence) | {'image_id'}
                or any(previous.get(key) != value for key, value in evidence.items())
                or not isinstance(previous['image_id'], str)
                or not DIGEST.fullmatch(previous['image_id'])):
            raise InstallError('Recorded prebuilt image or release selection changed')
        if _image_id(tag, runner) != previous['image_id']:
            raise InstallError('Previously imported image is missing or changed')
        _configuration('docker-daemon:' + tag, asset.config_digest, runner)
        if _image_id(tag, runner) != previous['image_id']:
            raise InstallError('Imported image changed during verification')
        return dict(previous)
    workspace = Path(workspace).absolute()
    try:
        info = workspace.lstat()
    except OSError:
        raise InstallError('Private image-import workspace is unavailable') from None
    if (workspace.resolve() != workspace or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise InstallError('Image import requires an owned mode-0700 workspace without symlinks')
    if runner(['docker', 'image', 'ls', '--no-trunc', '--quiet', tag],
              capture=True, timeout=30).strip():
        if intent is None:
            raise InstallError('Prebuilt image tag already exists without an import record; refusing replacement')
        identity = _image_id(tag, runner)
        _configuration('docker-daemon:' + tag, asset.config_digest, runner)
        if _image_id(tag, runner) != identity:
            raise InstallError('Imported image changed during verification')
        return dict(evidence, image_id=identity)
    with tempfile.TemporaryDirectory(prefix='core-image-', dir=workspace) as directory:
        archive = Path(directory) / 'image.tar'
        kit.copy_asset(role, archive)
        _configuration('docker-archive:' + str(archive), asset.config_digest, runner)
        runner(['skopeo', 'copy', 'docker-archive:' + str(archive), 'docker-daemon:' + tag],
               timeout=1800)
        identity = _image_id(tag, runner)
        _configuration('docker-daemon:' + tag, asset.config_digest, runner)
        if _image_id(tag, runner) != identity:
            raise InstallError('Imported image changed during verification')
    return dict(evidence, image_id=identity)
