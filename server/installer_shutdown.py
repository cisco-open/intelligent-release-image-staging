# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Durable, process-start-bound clean shutdown evidence for managed pods."""

import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile
import uuid


def _regular(path):
    info = path.lstat()
    if (path.resolve() != path or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077):
        raise ValueError('Unsafe shutdown evidence')
    return info


def _write(path, value):
    fd, temporary = tempfile.mkstemp(prefix='.iris-shutdown-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def paths(env):
    configured = env.get('IRIS_INSTALLER_SHUTDOWN_PROOF')
    if not configured:
        return None
    expected = Path(env['IRIS_STATE']).absolute() / 'installer-shutdown.json'
    runtime = Path(env['IRIS_RUN']).absolute() / 'installer-shutdown-nonce'
    pod = env['IRIS_POD_UID']
    if (str(expected) != configured or str(uuid.UUID(pod)) != pod
            or expected.parent.resolve() != expected.parent or runtime.parent.resolve() != runtime.parent):
        raise ValueError('Invalid managed shutdown configuration')
    return expected, runtime, pod


def prepare(env=os.environ):
    settings = paths(env)
    if settings is None:
        return
    proof, nonce, _pod = settings
    if proof.exists() or proof.is_symlink():
        _regular(proof)
        proof.unlink()
        descriptor = os.open(proof.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    if nonce.exists() or nonce.is_symlink():
        _regular(nonce)
    _write(nonce, secrets.token_hex(32).encode())


def record(children, env=os.environ):
    settings = paths(env)
    if settings is None:
        return
    proof, nonce, pod = settings
    _regular(nonce)
    value = nonce.read_text()
    if not re.fullmatch('[0-9a-f]{64}', value) or not 1 <= len(children) <= 16:
        raise ValueError('Missing process-start evidence')
    results = []
    for child in children:
        if not re.fullmatch(r'[1-9][0-9]*:(0|143)', child):
            raise ValueError('A managed writer did not stop cleanly')
        pid, code = map(int, child.split(':'))
        if any(item['pid'] == pid for item in results):
            raise ValueError('Duplicate managed writer')
        results.append({'pid': pid, 'exit_code': code})
    _write(proof, json.dumps({'pod_uid': pod, 'nonce': value, 'clean': True,
                              'children': results}, sort_keys=True).encode())


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['prepare']:
            prepare()
        elif sys.argv[1:2] == ['record']:
            record(sys.argv[2:])
        else:
            raise ValueError('Unknown shutdown evidence action')
    except (ValueError, OSError, KeyError):
        print('Managed shutdown evidence unavailable; consistent capture must be refused.', file=sys.stderr)
        raise SystemExit(1)
