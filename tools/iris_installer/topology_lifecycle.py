# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Bounded, non-shell PVC transport for stopped-writer maintenance helpers.

The caller owns the immutable helper and proves that every ordinary writer is
stopped. These routines never follow links, deserialize tar, or select a device
or Kubernetes resource from browser input. Partial snapshots remain private for
diagnosis; only a complete, twice-checked snapshot can become backup input.
"""

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess

from . import backup_archive
from .state import InstallError, atomic_write

CHUNK = 4 * 1024 * 1024
MAX_BATCH_MEMBERS = 128
MAX_BATCH_REQUEST = 1024 * 1024
MAX_CREDENTIAL = 32 * 1024 * 1024
MAX_LIVE_CIPHERTEXTS = 128 * 1024 * 1024
ROOTS = frozenset(('/data/config', '/data/state', '/data/images',
                   '/data/artifacts', '/data/image-state', '/data/log'))

_COMMON = '''import hashlib,json,os,stat,sys,tempfile
from pathlib import Path
allowed={'/data/config','/data/state','/data/images','/data/artifacts','/data/image-state','/data/log'}
root=Path(sys.argv[1])
if str(root) not in allowed or root.resolve()!=root: raise RuntimeError('storage root')
def relative(name):
 p=Path(name)
 if not name or p.is_absolute() or '..' in p.parts or str(p)!=name or any(ord(c)<32 for c in name): raise RuntimeError('member')
 path=root/p
 if path.resolve()!=path: raise RuntimeError('link')
 return path
def opened(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 s=os.fstat(fd)
 if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1:
  os.close(fd); raise RuntimeError('file custody')
 return fd,s
def fingerprint(s): return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode,s.st_uid,s.st_gid]
def digest(path):
 fd,s=opened(path)
 h=hashlib.sha256()
 with os.fdopen(fd,'rb') as f:
  for b in iter(lambda:f.read(1048576),b''): h.update(b)
  if fingerprint(s)!=fingerprint(os.fstat(f.fileno())): raise RuntimeError('writer')
 return h.hexdigest()
'''

_INVENTORY = _COMMON + '''
records=[]
def walk(path,name):
 if len(records)>=100000: raise RuntimeError('file count')
 s=path.lstat()
 if path.resolve()!=path or not(stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode)): raise RuntimeError('special file')
 if stat.S_ISREG(s.st_mode) and s.st_nlink!=1: raise RuntimeError('hardlink')
 entry={'name':name,'type':'directory' if stat.S_ISDIR(s.st_mode) else 'file','mode':stat.S_IMODE(s.st_mode),
        'uid':s.st_uid,'gid':s.st_gid,'size':0 if stat.S_ISDIR(s.st_mode) else s.st_size,'identity':fingerprint(s)}
 if entry['mode']&0o7000: raise RuntimeError('special mode')
 if entry['type']=='file': entry['sha256']=digest(path)
 records.append(entry)
 if entry['type']=='directory':
  for child in sorted(path.iterdir()): walk(child,child.name if not name else name+'/'+child.name)
walk(root,'')
encoded=json.dumps(records,separators=(',',':')).encode()
if len(encoded)>16777216: raise RuntimeError('inventory size')
sys.stdout.buffer.write(encoded)
'''

_READ = _COMMON + '''
path=relative(sys.argv[2]); offset=int(sys.argv[3]); length=int(sys.argv[4]); expected=json.loads(sys.argv[5])
if offset<0 or length<0 or length>4194304: raise RuntimeError('chunk bounds')
fd,s=opened(path)
with os.fdopen(fd,'rb') as f:
 if fingerprint(s)!=expected: raise RuntimeError('writer')
 f.seek(offset); data=f.read(length)
 if len(data)!=length or fingerprint(os.fstat(f.fileno()))!=expected: raise RuntimeError('writer')
sys.stdout.buffer.write(data)
'''

_READ_BATCH = _COMMON + '''
raw=sys.stdin.buffer.read(1048577)
if len(raw)>1048576: raise RuntimeError('batch request bounds')
records=json.loads(raw)
if not isinstance(records,list) or not 1<=len(records)<=128: raise RuntimeError('batch count')
seen=set(); total=0
for record in records:
 if not isinstance(record,dict) or set(record)!={'name','offset','length','identity'}: raise RuntimeError('batch record')
 name=record['name']; offset=record['offset']; length=record['length']; expected=record['identity']
 if not isinstance(name,str): raise RuntimeError('batch member')
 relative(name)
 if type(offset) is not int or offset<0 or type(length) is not int or not 0<length<=4194304: raise RuntimeError('chunk bounds')
 if not isinstance(expected,list) or len(expected)!=8 or any(type(n) is not int or n<0 for n in expected): raise RuntimeError('file identity')
 if offset+length>expected[2] or (name,offset) in seen: raise RuntimeError('duplicate or excessive chunk')
 seen.add((name,offset)); total+=length
 if total>4194304: raise RuntimeError('batch response bounds')
for record in records:
 path=relative(record['name']); expected=record['identity']
 fd,s=opened(path)
 with os.fdopen(fd,'rb') as f:
  if fingerprint(s)!=expected: raise RuntimeError('writer')
  f.seek(record['offset']); data=f.read(record['length'])
  if len(data)!=record['length'] or fingerprint(os.fstat(f.fileno()))!=expected: raise RuntimeError('writer')
 sys.stdout.buffer.write(data)
'''

_CIPHERS = _COMMON + '''
records=[]; total=0
for path in sorted(root.rglob('*')):
 if path.resolve()!=path: raise RuntimeError('configuration link')
 if not path.name.endswith('.age'): continue
 fd,s=opened(path); os.close(fd)
 total+=s.st_size
 if len(records)>=2048 or s.st_size>33554432 or total>134217728: raise RuntimeError('ciphertext bounds')
 records.append({'name':str(path.relative_to(root)),'size':s.st_size,'identity':fingerprint(s),'sha256':digest(path)})
sys.stdout.buffer.write(json.dumps(records,separators=(',',':')).encode())
'''

_WRITE = _COMMON + '''
path=relative(sys.argv[2])
header=sys.stdin.buffer.readline(8193)
if len(header)>8192 or not header.endswith(b'\\n'): raise RuntimeError('header')
record=json.loads(header)
if set(record)!={'before','after','mode','uid','gid','size'}: raise RuntimeError('record')
if record['mode'] not in (0o600,0o644,0o400,0o444) or record['uid'] not in (0,10001) or record['gid'] not in (0,10001): raise RuntimeError('custody')
if type(record['size']) is not int or not 0<=record['size']<=33554432: raise RuntimeError('size')
data=sys.stdin.buffer.read(record['size']+1)
if len(data)!=record['size'] or hashlib.sha256(data).hexdigest()!=record['after']: raise RuntimeError('candidate')
actual=digest(path) if path.exists() or path.is_symlink() else None
if actual not in (record['before'],record['after']): raise RuntimeError('unapproved change')
if not path.parent.is_dir() or path.parent.resolve()!=path.parent: raise RuntimeError('parent')
fd,temporary=tempfile.mkstemp(prefix='.iris-maintenance-',dir=path.parent)
try:
 with os.fdopen(fd,'wb') as out:
  os.fchmod(out.fileno(),record['mode']); os.fchown(out.fileno(),record['uid'],record['gid'])
  out.write(data); out.flush(); os.fsync(out.fileno())
 current=digest(path) if path.exists() or path.is_symlink() else None
 if current!=actual: raise RuntimeError('writer')
 os.replace(temporary,path)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try: os.fsync(fd)
 finally: os.close(fd)
finally:
 if os.path.exists(temporary): os.unlink(temporary)
print(record['after'])
'''


def _run(run, script, root, *arguments, input=None):
    if root not in ROOTS:
        raise InstallError('Unsupported PVC storage component')
    return run(['python3', '-I', '-B', '-c', script, root, *map(str, arguments)],
               input=input, capture=True)


def _inventory(run, root):
    raw = _run(run, _INVENTORY, root)
    if len(raw) > backup_archive.MAX_MANIFEST:
        raise InstallError('PVC inventory exceeds its limit')
    try:
        records = json.loads(raw)
    except (ValueError, UnicodeError):
        raise InstallError('Invalid PVC inventory') from None
    if not isinstance(records, list) or not 1 <= len(records) <= backup_archive.MAX_FILES:
        raise InstallError('Invalid PVC file count')
    seen, directories = set(), set()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise InstallError('Invalid PVC record')
        name = record.get('name')
        if not isinstance(name, str) or name in seen:
            raise InstallError('Duplicate or invalid PVC member')
        if index == 0:
            if name != '' or record.get('type') != 'directory':
                raise InstallError('Missing PVC root')
        else:
            backup_archive._name(name)
            parent = str(PurePosixPath(name).parent)
            if ('' if parent == '.' else parent) not in directories:
                raise InstallError('PVC parent missing or out of order')
        seen.add(name)
        kind = record.get('type')
        if (kind not in ('file', 'directory') or type(record.get('size')) is not int
                or record['size'] < 0 or type(record.get('mode')) is not int
                or not 0 <= record['mode'] <= 0o777
                or any(type(record.get(key)) is not int or record[key] < 0 for key in ('uid', 'gid'))
                or not isinstance(record.get('identity'), list) or len(record['identity']) != 8
                or any(type(value) is not int or value < 0 for value in record['identity'])):
            raise InstallError('Invalid PVC metadata')
        if kind == 'directory':
            if record['size'] != 0:
                raise InstallError('Invalid PVC directory size')
            directories.add(name)
        elif not re.fullmatch('[0-9a-f]{64}', str(record.get('sha256', ''))):
            raise InstallError('Missing PVC digest')
    return records


def _snapshot_chunks(run, root, records):
    """Batch tiny reads without caching or bypassing a helper admission fence.

    The validated request supplies the framing: exact ordered byte lengths,
    not helper-provided paths or lengths. A batch remains at most one normal
    chunk in bytes and 128 members, with bounded request metadata. Every call
    uses the original transport and therefore its full stopped-writer checks.
    """
    batch, size, metadata_size = [], 0, 2

    def read(members):
        request = json.dumps(members, separators=(',', ':')).encode()
        if len(request) > MAX_BATCH_REQUEST:
            raise InstallError('PVC batch metadata exceeds its bound')
        data = _run(run, _READ_BATCH, root, input=request)
        if len(data) != sum(item['length'] for item in members):
            raise InstallError('Truncated or excessive PVC snapshot batch')
        position = 0
        for item in members:
            end = position + item['length']
            yield data[position:end]
            position = end

    for record in records:
        if record['type'] != 'file':
            continue
        for offset in range(0, record['size'], CHUNK):
            length = min(CHUNK, record['size'] - offset)
            member = dict(name=record['name'], offset=offset, length=length,
                          identity=record['identity'])
            encoded_size = len(json.dumps(member, separators=(',', ':')).encode())
            if batch and (len(batch) >= MAX_BATCH_MEMBERS or size + length > CHUNK
                          or metadata_size + 1 + encoded_size > MAX_BATCH_REQUEST):
                yield from read(batch)
                batch, size, metadata_size = [], 0, 2
            metadata_size += encoded_size + (1 if batch else 0)
            batch.append(member)
            size += length
    if batch:
        yield from read(batch)


def snapshot_tree(run, root, destination, *, max_bytes=1024 ** 4):
    """Copy a stopped PVC component with bounded chunks and end-to-end hashes.

    ``run`` is an owned-helper argv transport, never a shell command. The NEW
    destination is retained on failure and must not be reused as a valid backup.
    """
    destination = Path(destination).absolute()
    backup_archive.private_directory(destination.parent)
    private_state = root in ('/data/config', '/data/state', '/data/log')
    if private_state and subprocess.check_output(
            ['stat', '-f', '-c', '%T', str(destination.parent)],
            env={'PATH': '/usr/bin:/bin'}).strip() != b'tmpfs':
        raise InstallError('Credential and state snapshots require memory-backed custody')
    if destination.exists() or destination.is_symlink():
        raise InstallError('Choose a new PVC snapshot destination')
    records = _inventory(run, root)
    total = sum(record['size'] for record in records)
    headroom = max(64 * 1024 ** 2 if private_state else 1024 ** 3, len(records) * 4096)
    if total > max_bytes or shutil.disk_usage(destination.parent).free < int(total * 1.2) + headroom:
        raise InstallError('Insufficient bounded PVC snapshot space')
    destination.mkdir(mode=0o700)
    chunks = _snapshot_chunks(run, root, records)
    for record in records[1:]:
        path = destination / record['name']
        if record['type'] == 'directory':
            path.mkdir(mode=0o700)
            continue
        value = hashlib.sha256()
        with path.open('xb') as output:
            os.fchmod(output.fileno(), 0o600)
            for offset in range(0, record['size'], CHUNK):
                length = min(CHUNK, record['size'] - offset)
                chunk = next(chunks)
                if len(chunk) != length:
                    raise InstallError('Truncated PVC snapshot chunk')
                value.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if value.hexdigest() != record['sha256']:
            raise InstallError('PVC snapshot digest mismatch')
    if next(chunks, None) is not None:
        raise InstallError('Unexpected PVC snapshot chunk')
    if _inventory(run, root) != records:
        raise InstallError('PVC changed during stopped-writer capture')
    # The containing directory stays caller-owned 0700. Preserve the source's
    # ownership and modes underneath that private boundary for archive fidelity
    # and credential candidate custody, without exposing snapshot contents.
    for record in reversed(records):
        path = destination / record['name']
        os.chown(path, record['uid'], record['gid'])
        path.chmod(record['mode'])
    atomic_write(destination.parent / (destination.name + '-inventory.json'),
                 json.dumps(records, sort_keys=True).encode())
    return records


def compare_write(run, root, name, before, content, *, mode=0o600, uid=10001, gid=10001):
    """Publish only an old-or-approved credential in the stopped PVC helper."""
    backup_archive._name(name)
    if before is not None and not re.fullmatch('[0-9a-f]{64}', str(before)):
        raise InstallError('Invalid original credential digest')
    if not isinstance(content, bytes) or len(content) > MAX_CREDENTIAL:
        raise InstallError('Credential candidate exceeds its bound')
    if mode not in (0o600, 0o644, 0o400, 0o444) or uid not in (0, 10001) or gid not in (0, 10001):
        raise InstallError('Unsupported credential custody')
    after = hashlib.sha256(content).hexdigest()
    record = dict(before=before, after=after, mode=mode, uid=uid, gid=gid, size=len(content))
    result = _run(run, _WRITE, root, name,
                  input=json.dumps(record, sort_keys=True).encode() + b'\n' + content)
    if result.strip() != after.encode():
        raise InstallError('PVC credential publication lacks matching proof')
    return after


def read_ciphertexts(run):
    """Read actual running-server ciphertexts, never a stopped host mirror.

    Writers may publish atomic ciphertext replacements. A replacement during
    the two-pass read refuses proof; the caller can retry the approved operation
    after obtaining a stable read. Unrelated plaintext audit writes are ignored.
    """
    root = '/data/config'

    def inventory():
        raw = _run(run, _CIPHERS, root)
        if len(raw) > backup_archive.MAX_MANIFEST:
            raise InstallError('Live ciphertext inventory exceeds its bound')
        records = json.loads(raw)
        if not isinstance(records, list) or not 1 <= len(records) <= 2048:
            raise InstallError('Live ciphertext inventory is missing or excessive')
        names, total = set(), 0
        for record in records:
            if not isinstance(record, dict) or set(record) != {'name', 'size', 'identity', 'sha256'}:
                raise InstallError('Invalid live ciphertext record')
            name = record['name']
            if not isinstance(name, str):
                raise InstallError('Invalid live ciphertext path')
            backup_archive._name(name)
            if name in names or not name.endswith('.age'):
                raise InstallError('Duplicate or unencrypted live ciphertext path')
            names.add(name)
            if (type(record['size']) is not int or not 0 <= record['size'] <= MAX_CREDENTIAL
                    or not re.fullmatch('[0-9a-f]{64}', str(record['sha256']))
                    or not isinstance(record['identity'], list) or len(record['identity']) != 8
                    or any(type(value) is not int or value < 0 for value in record['identity'])):
                raise InstallError('Invalid live ciphertext metadata')
            total += record['size']
        if total > MAX_LIVE_CIPHERTEXTS:
            raise InstallError('Live ciphertext total exceeds its bound')
        return records

    records = inventory()
    contents = {}
    for record in records:
        content = bytearray()
        for offset in range(0, record['size'], CHUNK):
            length = min(CHUNK, record['size'] - offset)
            chunk = _run(run, _READ, root, record['name'], offset, length,
                         json.dumps(record['identity']))
            if len(chunk) != length:
                raise InstallError('Truncated live ciphertext')
            content.extend(chunk)
        if hashlib.sha256(content).hexdigest() != record['sha256']:
            raise InstallError('Live ciphertext digest changed')
        contents[record['name']] = bytes(content)
    if inventory() != records:
        raise InstallError('Live encrypted state changed during consumer verification')
    return contents
