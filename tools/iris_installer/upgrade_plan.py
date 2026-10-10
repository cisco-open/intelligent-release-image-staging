# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Closed generation and publication contracts for managed Docker upgrades.

These helpers never start a service, replace a journal or alter stored data.
The application-upgrade transaction owns admission, writer fencing and recovery.
"""

import copy
import hashlib
import json
from pathlib import Path
import re
import uuid

from .state import InstallError


SCHEMA = 'iris-application-upgrade-plan/v1'
SERVICES = ('iris', 'console')
NATIVE_FILES = frozenset(name + suffix for name in
    ('iris-amd64.tar', 'iris-arm64.tar', 'iris-xr.rpm') for suffix in ('', '.manifest'))
GUEST_FILES = frozenset(name + suffix for name in
    ('iris-agent.tgz', 'iris-agent-arm64.tgz') for suffix in ('', '.sha256'))
BUILD_FILES = NATIVE_FILES | GUEST_FILES | {'device.oci.tar', 'device.oci.tar.manifest'}


def require(value, message):
    if not value:
        raise InstallError(message)


def identifier(value):
    try:
        valid = isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        valid = False
    require(valid, 'Use a canonical application upgrade operation ID')
    return value


def sha256(value):
    require(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value),
            'Application upgrade evidence requires exact SHA256 values')
    return value


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=True, allow_nan=False).encode('ascii')
    except (TypeError, ValueError):
        raise InstallError('Application upgrade evidence is not canonical JSON') from None


def fingerprint(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_manifest(value, *, expected=None):
    require(isinstance(value, dict) and 0 < len(value) <= 10000,
            'Application upgrade file inventory is missing or oversized')
    for name, digest in value.items():
        require(isinstance(name, str) and 0 < len(name) <= 1024,
                'Invalid application upgrade inventory path')
        path = Path(name)
        require(path.parts and not path.is_absolute() and '..' not in path.parts and str(path) == name
                and all(ord(character) >= 32 and ord(character) != 127 for character in name),
                'Application upgrade inventory escapes its reserved directory')
        sha256(digest)
    require(expected is None or set(value) == set(expected),
            'Application upgrade package inventory is incomplete or unexpected')
    return copy.deepcopy(value)


def worker_manifest(value):
    result = file_manifest(value)
    require(all(re.fullmatch(r'[a-z][a-z0-9_]*\.py|__init__\.py', name) for name in result)
            and {'__init__.py', 'managed_worker.py', 'lifecycle_worker.py', 'state.py'} <= set(result),
            'Application upgrade worker runtime is incomplete')
    return result


def require_source_build(journal):
    """A source transition cannot silently reinterpret a selected release kit."""
    require(isinstance(journal, dict) and type(journal.get('schema')) is int and journal['schema'] == 1,
            'A finished installer-owned deployment is required')
    identifier(journal.get('id'))
    require(isinstance(journal.get('config'), dict) and journal['config'].get('target') == 'docker',
            'Managed application upgrade currently supports Docker on one host')
    from .prebuilt_install import selected
    require(not selected(journal) and not any(str(key).startswith('prebuilt_') for key in journal),
            'Prebuilt release-kit upgrades require a separately supported transition')
    require(isinstance(journal.get('completed'), dict)
            and {'prepared', 'images', 'packages', 'signing', 'guestshell'} <= set(journal['completed'])
            and journal.get('state') in ('OWNER_CLAIM_REQUIRED', 'PRODUCTION_REVIEW_REQUIRED'),
            'Finish the existing installation before preparing an upgrade')
    file_manifest(journal.get('source_manifest'))
    require(isinstance(journal.get('root_digests'), dict) and len(journal['root_digests']) == 2,
            'Existing instruction root identities are required')
    for name, digest in journal['root_digests'].items():
        require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*\.pub', name),
                'Invalid existing instruction root identity')
        sha256(digest)
    sha256(journal['completed']['prepared'])
    file_manifest(journal['completed']['packages'], expected=NATIVE_FILES)


def runtime_contract(compose):
    """Compare shipped runtime layout; build context and image pins may change."""
    require(isinstance(compose, dict) and isinstance(compose.get('services'), dict)
            and set(compose['services']) == set(SERVICES),
            'Application upgrade requires exactly the server and Console services')
    result = copy.deepcopy(compose)
    for service in result['services'].values():
        require(isinstance(service, dict), 'Invalid application service declaration')
        service.pop('build', None)
        service.pop('image', None)
    return result


def candidate_compose(current, old_template, new_template, images):
    """Keep live settings, including recorded credential-rotation overrides.

    The first supported transition refuses a release that changes its runtime
    layout. It does not guess how to merge new defaults into owner state.
    """
    require(canonical(runtime_contract(old_template)) == canonical(runtime_contract(new_template)),
            'This release changes the Docker runtime layout; do not bypass the managed upgrade guard')
    runtime_contract(current)
    require(isinstance(images, dict) and set(images) == set(SERVICES),
            'Both approved application images are required')
    result = copy.deepcopy(current)
    for name in SERVICES:
        require(isinstance(images[name], str) and re.fullmatch(r'sha256:[0-9a-f]{64}', images[name]),
                'Use exact immutable application image IDs')
        result['services'][name]['image'] = images[name]
        # There is never a build or pull during cutover or later resume.
        result['services'][name].pop('build', None)
        result['services'][name]['pull_policy'] = 'never'
    return result


def startup_compose(final):
    """A crash cannot auto-start an unverified candidate after host reboot."""
    result = copy.deepcopy(final)
    runtime_contract(result)
    for service in result['services'].values():
        service['restart'] = 'no'
    return result


def next_journal(original, *, operation_id, source, compose, packages, guestshell):
    """Derive only an approved code generation, preserving all owner authority."""
    require_source_build(original)
    identifier(operation_id)
    file_manifest(source)
    file_manifest(packages, expected=NATIVE_FILES)
    require(canonical(source) != canonical(original['source_manifest']), 'The candidate source is already installed')
    runtime_contract(compose)
    require(isinstance(guestshell, dict) and guestshell.get('state') == 'ok',
            'A verified served Guest Shell bundle is required before completion')
    images = {}
    for service in compose['services'].values():
        image = service.get('image')
        require(isinstance(image, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', image),
                'The completed upgrade must retain immutable application images')
        images[image] = image
    result = copy.deepcopy(original)
    result['source_manifest'] = copy.deepcopy(source)
    result['completed'].update(prepared=hashlib.sha256(canonical(compose)).hexdigest(),
                               images=images, packages=copy.deepcopy(packages),
                               guestshell=copy.deepcopy(guestshell))
    result['state'] = 'PRODUCTION_REVIEW_REQUIRED'
    history = result.setdefault('application_upgrades', [])
    require(isinstance(history, list) and len(history) < 100
            and all(isinstance(row, dict) and row.get('operation_id') != operation_id for row in history),
            'Application upgrade history is invalid, reused or full')
    history.append({'operation_id': operation_id,
                    'previous_source_sha256': fingerprint(original['source_manifest']),
                    'source_sha256': fingerprint(source)})
    return result
