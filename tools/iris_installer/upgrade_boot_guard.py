# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Pinned systemd pre-start guard for workers that predate upgrade support.

The running old worker is gracefully stopped by the transaction. This drop-in
also prevents a reboot between durable fence intent and stop/disable from
starting that old, unguarded runtime. Unknown administrator drop-ins are refused.
"""

import hashlib
import json
import os
from pathlib import Path
import stat

from . import managed_worker, upgrade_plan as plan, upgrade_state
from .state import InstallError, atomic_write, regular_bytes

NAME = '40-iris-application-upgrade.conf'


def _directory(path):
    if not path.exists() and not path.is_symlink():
        return False
    managed_worker._path(path)
    info = path.lstat()
    plan.require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                 'Worker upgrade guard directory has unsafe custody')
    plan.require({child.name for child in path.iterdir()} <= {NAME},
                 'Unrelated systemd drop-ins exist; review them before upgrading')
    return True


def _paths(base, worker):
    directory = managed_worker.UNIT_DIRECTORY / (worker['unit'] + '.d')
    return directory, directory / NAME


def _loaded(worker):
    lines = managed_worker.command(['systemctl', 'show', worker['unit'], '--property=DropInPaths']).decode().splitlines()
    plan.require(len(lines) == 1 and lines[0].startswith('DropInPaths='),
                 'Cannot inspect the worker systemd drop-in authority')
    return lines[0].removeprefix('DropInPaths=').split()


def launcher(base, operation_id, runtime, instance_id):
    """Standalone protected code verifies every module before importing it."""
    directory = managed_worker._runtime_directory(base, {'runtime': runtime})
    code = '''# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
import hashlib,json,os,stat,sys
from pathlib import Path
base=Path(BASE)
package=Path(PACKAGE)
def protected(path,directory=False):
 if path.resolve()!=path: raise RuntimeError('upgrade guard link')
 for parent in (path.parent,*path.parent.parents):
  info=parent.lstat()
  if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022: raise RuntimeError('upgrade guard parent')
 info=path.lstat()
 if info.st_uid!=0 or info.st_mode&0o022 or (not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1)): raise RuntimeError('upgrade guard custody')
def read(path):
 protected(path)
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  data=f.read(4194305)
 if len(data)>4194304: raise RuntimeError('upgrade guard input limit')
 return data
try:
 protected(Path(__file__))
 if {p.name for p in package.iterdir() if p.suffix=='.py'}!=set(MANIFEST): raise RuntimeError('upgrade runtime inventory')
 for name,digest in MANIFEST.items():
  if hashlib.sha256(read(package/name)).hexdigest()!=digest: raise RuntimeError('upgrade runtime changed')
 record=json.loads(read(base/'worker-service.json'))
 if record.get('instance_id')!=INSTANCE or record.get('state_dir')!=str(base): raise RuntimeError('upgrade worker identity')
 sys.path.insert(0,str(package.parent))
 from iris_installer.upgrade_state import guard
 guard(base,instance_id=INSTANCE,inspection=(json.dumps(record.get('runtime'),sort_keys=True,separators=(',',':'))==json.dumps(MANIFEST,sort_keys=True,separators=(',',':'))))
except Exception:
 print('IRIS worker start refused: recover the approved application upgrade.',file=sys.stderr)
 raise SystemExit(1)
'''
    assignments = ('BASE=' + repr(str(base)) + '\nPACKAGE=' + repr(str(directory / 'iris_installer')) +
                   '\nMANIFEST=' + repr(runtime) + '\nINSTANCE=' + repr(plan.identifier(instance_id)) + '\n')
    # Constants are Python literals, not a shell or environment expansion.
    return code.replace('base=Path(BASE)', assignments + 'base=Path(BASE)').encode('utf-8')


def dropin(base, operation_id):
    path = base / 'application-upgrades' / plan.identifier(operation_id) / 'worker-start-guard.py'
    return ('# Copyright 2026 Cisco Systems, Inc. and its affiliates\n'
            '# SPDX-License-Identifier: Apache-2.0\n[Service]\n'
            'ExecStartPre=/usr/bin/python3 -I -B ' + managed_worker._quote(path) + '\n').encode()


def describe(base, worker, *, expected=None):
    """Accept no drop-in or the exact previous completed upgrade's guard."""
    directory, path = _paths(base, worker)
    exists = _directory(directory) and path.exists()
    loaded = _loaded(worker)
    if not exists:
        plan.require(not loaded, 'An unknown systemd worker drop-in is loaded')
        return None
    plan.require(loaded == [str(path)], 'Unexpected effective worker drop-ins')
    selected = expected
    if selected is None:
        # A later isolated candidate owns the current operation pointer, not
        # the still-running worker's guard. Its exact preimage retains that
        # authority; active or interrupted operations must still refuse.
        upgrade_state.guard(base, instance_id=worker['instance_id'])
        selected = upgrade_state.read(base / 'application-upgrade.json')
        current_id = plan.identifier(selected.get('operation_id'))
        current = upgrade_state.validate(
            upgrade_state.read(base / 'application-upgrades' / current_id / 'record.json'),
            operation_id=current_id, instance_id=worker['instance_id'])
        if current['phase'] in ('building', 'prepared', 'cancelled'):
            previous = current.get('worker_before')
            plan.require(isinstance(previous, dict) and
                         plan.canonical(previous.get('record')) == plan.canonical(worker),
                         'The prepared upgrade worker preimage changed')
            selected = expected = previous.get('boot_guard')
            plan.require(isinstance(selected, dict) and set(selected) ==
                         {'operation_id', 'dropin_sha256', 'launcher_sha256'},
                         'The previous worker upgrade guard proof is missing')
    operation_id = plan.identifier(selected.get('operation_id'))
    saved = upgrade_state.read(base / 'application-upgrades' / operation_id / 'record.json')
    upgrade_state.validate(saved, operation_id=operation_id, instance_id=worker['instance_id'])
    plan.require(saved['phase'] == 'upgraded', 'Recover the previous application upgrade before preparing another')
    code = launcher(base, operation_id, saved['candidate']['selection']['runtime'], worker['instance_id'])
    actual_code = managed_worker._file(base / 'application-upgrades' / operation_id / 'worker-start-guard.py')
    actual = managed_worker._file(path, mode=0o644)
    plan.require(actual == dropin(base, operation_id) and actual_code == code,
                 'Existing owned worker upgrade guard changed')
    observed = {'operation_id': operation_id, 'dropin_sha256': hashlib.sha256(actual).hexdigest(),
                'launcher_sha256': hashlib.sha256(code).hexdigest()}
    plan.require(expected is None or plan.canonical(expected) == plan.canonical(observed),
                 'The previous worker upgrade guard proof changed')
    return observed


def install(base, operation, saved):
    """Write intent before guard publication; active fence follows verification."""
    runtime = operation.record['candidate']['selection']['runtime']
    plan.require(plan.canonical(runtime) == plan.canonical(managed_worker._runtime_manifest()),
                 'The approved boot-guard runtime changed')
    worker = saved['record']
    directory, path = _paths(base, worker)
    expected_code = launcher(base, operation.id, runtime, worker['instance_id'])
    expected_dropin = dropin(base, operation.id)
    intent = {'previous': saved.get('boot_guard'), 'dropin_sha256': hashlib.sha256(expected_dropin).hexdigest(),
              'launcher_sha256': hashlib.sha256(expected_code).hexdigest()}
    previous_intent = operation.record.get('boot_guard_intent')
    plan.require(previous_intent is None or plan.canonical(previous_intent) == plan.canonical(intent),
                 'Recorded worker guard intent changed')
    if previous_intent is None:
        plan.require(describe(base, worker, expected=saved.get('boot_guard')) == saved.get('boot_guard'),
                     'Worker drop-ins changed since review')
        operation.record['boot_guard_intent'] = intent
        operation.save()
    managed_worker._runtime(base, dict(worker, runtime=runtime))
    code_path = operation.directory / 'worker-start-guard.py'
    if code_path.exists() or code_path.is_symlink():
        plan.require(managed_worker._file(code_path) == expected_code, 'Worker pre-start code changed')
    else:
        atomic_write(code_path, expected_code)
    if not _directory(directory):
        directory.mkdir(mode=0o755)
    if path.exists() or path.is_symlink():
        actual = managed_worker._file(path, mode=0o644)
        accepted = {expected_dropin}
        if saved.get('boot_guard'):
            accepted.add(dropin(base, saved['boot_guard']['operation_id']))
        plan.require(actual in accepted, 'Worker pre-start drop-in changed')
    atomic_write(path, expected_dropin, 0o644)
    from .restore_storage import sync
    sync(directory.parent)
    managed_worker.command(['systemctl', 'daemon-reload'])
    plan.require(_loaded(worker) == [str(path)] and managed_worker._file(path, mode=0o644) == expected_dropin,
                 'Worker pre-start guard is not the effective systemd configuration')
    operation.record['boot_guard_installed'] = intent
    operation.save()


def verify(base, operation, saved):
    """An active fence never repairs a missing or tampered startup guard."""
    runtime = operation.record['candidate']['selection']['runtime']
    expected_code = launcher(base, operation.id, runtime, saved['record']['instance_id'])
    expected_dropin = dropin(base, operation.id)
    expected_intent = {'previous': saved.get('boot_guard'),
        'dropin_sha256': hashlib.sha256(expected_dropin).hexdigest(),
        'launcher_sha256': hashlib.sha256(expected_code).hexdigest()}
    plan.require(plan.canonical(operation.record.get('boot_guard_installed')) == plan.canonical(expected_intent)
                 and plan.canonical(operation.record.get('boot_guard_intent')) == plan.canonical(expected_intent),
                 'Active worker startup guard proof is missing or changed')
    directory, path = _paths(base, saved['record'])
    plan.require(_directory(directory) and _loaded(saved['record']) == [str(path)]
                 and managed_worker._file(path, mode=0o644) == expected_dropin
                 and managed_worker._file(operation.directory / 'worker-start-guard.py') == expected_code,
                 'The active worker startup guard changed; preserve it for inspection')
    package = managed_worker._runtime_directory(base, {'runtime': runtime}) / 'iris_installer'
    managed_worker._path(package)
    plan.require({path.name for path in package.glob('*.py')} == set(runtime),
                 'The pinned worker guard runtime inventory changed')
    for name, digest in runtime.items():
        plan.require(hashlib.sha256(managed_worker._file(package / name)).hexdigest() == digest,
                     'The pinned worker guard runtime changed')
