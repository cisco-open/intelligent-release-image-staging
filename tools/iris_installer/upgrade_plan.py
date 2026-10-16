# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shared validation and historical operation contracts.

Uninstall and retained worker/archive guards reuse these pure validators. No
application replacement or upgrade execution is provided by this module.
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
    ('iris-agent.tgz', 'iris-agent-arm.tgz') for suffix in ('', '.sha256'))
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
