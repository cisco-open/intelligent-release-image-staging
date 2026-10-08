# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Bounded restore publication inside the owned, isolated Kubernetes helper."""

import json
from pathlib import Path

from . import restore_storage
from .state import InstallError

# The exact audited storage implementation is transported as code. Paths and
# content travel as separate argv/stdin values and never enter a shell.
def _code():
    code = Path(restore_storage.__file__).read_text()
    return code.replace('from .state import InstallError, atomic_write',
                        'class InstallError(Exception): pass')


def _run(install, operation, script, *args, input=None):
    if len(operation) != 36 or any(c not in '0123456789abcdef-' for c in operation):
        raise InstallError('Invalid restore helper operation')
    return install.maintenance_run(['python3', '-I', '-B', '-c', _code() + '\n' + script,
                                    operation, *map(str, args)], input=input, capture=True)


_SETUP = '''
import sys
operation, component=sys.argv[1:]
if component not in ('config','state','log','images','artifacts'): raise InstallError('component')
target=Path('/data')/component
staged=target.with_name('.iris-restore-'+operation+'-'+component)
retained=target.with_name('.iris-retained-'+operation+'-'+component)
'''


def stage(install, operation, component, source, records):
    """Transfer files in bounded chunks; incomplete candidates stay private."""
    expected = restore_storage.fingerprint(records)
    result = _run(install, operation, _SETUP.replace('sys.argv[1:]', 'sys.argv[1:3]') + '''
if retained.exists(): raise InstallError('publication already admitted')
if staged.exists() or staged.is_symlink():
 if fingerprint(inventory(staged))==sys.argv[3]:
  print('ready'); sys.exit(0)
 os.rename(staged,staged.with_name(staged.name+'-incomplete-'+str(uuid.uuid4())))
 sync(staged.parent)
if shutil.disk_usage(target.parent).free<int(sys.argv[4])+1073741824: raise InstallError('restore capacity')
staged.mkdir(mode=0o700)
print('new')
''', component, expected, sum(row['size'] for row in records)).decode().strip()
    if result == 'ready':
        return
    if result != 'new':
        raise InstallError('PVC restore candidate reservation failed')
    for record in records[1:]:
        name = record['name']
        if record['type'] == 'directory':
            _run(install, operation, _SETUP.replace('sys.argv[1:]', 'sys.argv[1:3]') + '''
path=staged/sys.argv[3]
if path.resolve()!=path or staged not in path.parents: raise InstallError('path')
path.mkdir(mode=0o700)
''', component, name)
        else:
            with (Path(source) / name).open('rb') as stream:
                offset = 0
                while True:
                    data = stream.read(4 * 1024 * 1024)
                    _run(install, operation, _SETUP.replace('sys.argv[1:]', 'sys.argv[1:3]') + '''
path=staged/sys.argv[3]; offset=int(sys.argv[4])
if path.resolve()!=path or staged not in path.parents: raise InstallError('path')
data=sys.stdin.buffer.read(4194305)
if len(data)>4194304: raise InstallError('chunk bounds')
with path.open('xb' if offset==0 else 'r+b') as out:
 if out.seek(0,2)!=offset: raise InstallError('offset')
 out.write(data); out.flush(); os.fsync(out.fileno())
''', component, name, offset, input=data)
                    offset += len(data)
                    if len(data) < 4 * 1024 * 1024:
                        break
    raw = json.dumps(records, sort_keys=True).encode()
    result = _run(install, operation, _SETUP + '''
records=json.loads(sys.stdin.buffer.read(16777217))
apply_metadata(staged,records)
if inventory(staged)!=records: raise InstallError('candidate differs')
sync(staged.parent)
print(fingerprint(records))
''', component, input=raw).decode().strip()
    if result != restore_storage.fingerprint(records):
        raise InstallError('PVC restore candidate verification failed')


def publish(install, operation, component, before, after):
    result = _run(install, operation, _SETUP.replace('sys.argv[1:]', 'sys.argv[1:3]') + '''
publish(target,staged,retained,sys.argv[3],sys.argv[4])
print(sys.argv[4])
''', component, before, after).decode().strip()
    if result != after:
        raise InstallError('PVC restore publication lacks matching evidence')
