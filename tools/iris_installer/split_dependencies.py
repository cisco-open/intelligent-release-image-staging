# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Authenticated local-only dependency plans for the selected remote Console.

The remote baseline is Ubuntu apt/dpkg/gpgv/keyring, Python 3, pinned SSH and
noninteractive sudo. This transports authenticated data and reviewed installer
helpers, not a shell installer or a source/network fallback.
"""

import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shlex
import shutil
import stat
import subprocess
import tempfile
import time

from . import offline_inputs, release_kit
from .state import InstallError, regular_bytes


SOURCES = ('__init__.py', 'state.py', 'release_kit.py', 'ubuntu.py',
           'offline_dependencies.py', 'offline_inputs.py', 'prebuilt_dependencies.py',
           'split_dependencies.py')
MAX_HELPER = 1024 * 1024
MAX_JSON = 1024 * 1024
TRANSFER_TIMEOUT = 7200
ROLE = 'ubuntu-dependencies'
REMOTE_ROOTS = frozenset(('docker.io', 'docker-compose-v2', 'openssl'))
RECORD = 'split_dependency_provisioning'
PLAN = 'iris-split-dependency-plan-v1'
DONE = 'iris-split-dependency-result-v1'

# This fixed bootstrap verifies the externally pinned header, every source
# module and the complete closure before importing any transported code.
# Python modules stay in memory, through a closed package-only import loader.
BOOTSTRAP = r'''
import hashlib,importlib.abc,importlib.util,json,os,pathlib,shutil,stat,sys,tempfile
def fail(): raise RuntimeError('Authenticated dependency transport failed')
def exact(size):
 data=sys.stdin.buffer.read(size)
 if len(data)!=size: fail()
 return data
def unique(pairs):
 value={}
 for key,item in pairs:
  if key in value: fail()
  value[key]=item
 return value
work=None; directory=None
try:
 if os.geteuid()!=0: fail()
 length=int.from_bytes(exact(8),'big')
 if not 0<length<=1024*1024: fail()
 raw=exact(length)
 if hashlib.sha256(raw).hexdigest()!=sys.argv[1]: fail()
 header=json.loads(raw,object_pairs_hook=unique)
 if set(header)!={'schema','request','files'} or header['schema']!='iris-split-dependency-wire-v1': fail()
 names=['__init__.py','state.py','release_kit.py','ubuntu.py','offline_dependencies.py','offline_inputs.py','prebuilt_dependencies.py','split_dependencies.py','closure.tar.gz']
 if not isinstance(header['files'],list) or [row.get('name') for row in header['files']]!=names: fail()
 work=pathlib.Path(tempfile.mkdtemp(prefix='iris-split-dependencies-'))
 directory=os.open(work,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 held=os.fstat(directory); modules={}
 for row in header['files']:
  if set(row)!={'name','size','sha256'} or type(row['size']) is not int: fail()
  limit=8*1024**3 if row['name']=='closure.tar.gz' else 1024*1024
  if not 0<row['size']<=limit: fail()
  if row['name']=='closure.tar.gz':
   fd=os.open(row['name'],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
   digest=hashlib.sha256(); remaining=row['size']
   with os.fdopen(fd,'wb') as output:
    while remaining:
     data=exact(min(remaining,1024*1024)); remaining-=len(data)
     digest.update(data); output.write(data)
   actual=digest.hexdigest()
  else:
   data=exact(row['size']); actual=hashlib.sha256(data).hexdigest()
   name='iris_installer' if row['name']=='__init__.py' else 'iris_installer.'+row['name'][:-3]
   modules[name]=data
  if actual!=row['sha256']: fail()
 if sys.stdin.buffer.read(1): fail()
 named=work.lstat()
 if work.resolve()!=work or (named.st_dev,named.st_ino)!=(held.st_dev,held.st_ino): fail()
 class Loader(importlib.abc.MetaPathFinder,importlib.abc.Loader):
  def find_spec(self,fullname,path=None,target=None):
   if fullname in modules: return importlib.util.spec_from_loader(fullname,self,is_package=fullname=='iris_installer')
  def create_module(self,spec): return None
  def exec_module(self,module):
   module.__file__='<authenticated:'+module.__name__+'>'
   exec(compile(modules[module.__name__],module.__file__,'exec'),module.__dict__)
 sys.meta_path.insert(0,Loader())
 from iris_installer.split_dependencies import perform_remote
 result=perform_remote(work/'closure.tar.gz',header['request'])
 print(json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False))
except Exception:
 sys.stderr.write('Remote authenticated dependency operation failed; preserve the accepted plan\n')
 sys.exit(1)
finally:
 if directory is not None:
  try:
   for name in os.listdir(directory):
    if stat.S_ISDIR(os.stat(name,dir_fd=directory,follow_symlinks=False).st_mode): shutil.rmtree(name,dir_fd=directory)
    else: os.unlink(name,dir_fd=directory)
   try: named=work.lstat()
   except FileNotFoundError: pass
   else:
    held=os.fstat(directory)
    if (named.st_dev,named.st_ino)==(held.st_dev,held.st_ino): work.rmdir()
  finally: os.close(directory)
'''


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _fields(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise InstallError('Remote dependency receipt has unsupported or missing fields')


def _helper_hashes(deployment):
    inventory = deployment.journal.document['source_manifest']
    result = {}
    for name in SOURCES:
        digest = inventory.get('tools/iris_installer/' + name)
        release_kit._sha(digest)
        result[name] = digest
    return result


def _source_bytes(deployment, expected):
    result = {}
    for name in SOURCES:
        path = deployment.source / 'tools/iris_installer' / name
        fd, before = release_kit._open(path, MAX_HELPER)
        try:
            data = io.BytesIO()
            digest, size = release_kit._hash(fd, MAX_HELPER, data)
            if (digest != expected[name] or size != before.st_size
                    or release_kit._identity(before) != release_kit._identity(os.fstat(fd))):
                raise InstallError('Remote dependency helper differs from authenticated installer source')
            result[name] = data.getvalue()
        finally:
            os.close(fd)
    return result


def _run_remote(command, environment, wire):
    """Bound a child's response while receiving it, including early termination."""
    process = None
    try:
        process = subprocess.Popen(command, env=environment, stdin=wire,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        deadline, received = time.monotonic() + TRANSFER_TIMEOUT, bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise InstallError('Remote dependency operation timed out; preserve the accepted plan')
                chunk = os.read(process.stdout.fileno(), min(65536, MAX_JSON + 1 - len(received)))
                if not chunk:
                    break
                received.extend(chunk)
                if len(received) > MAX_JSON:
                    raise InstallError('Remote dependency response exceeds its size limit')
        result = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        if result:
            raise InstallError('Remote dependency operation failed; preserve the accepted plan')
        if not received:
            raise InstallError('Remote dependency response is empty')
        return release_kit._json(received)
    except (OSError, subprocess.SubprocessError):
        raise InstallError('Remote dependency transfer did not complete; preserve the accepted plan') from None
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()


def _exchange(deployment, kit, request, helpers):
    """Stream a bounded private input file; neither closure nor SSH output is RAM-sized."""
    if deployment.transport_fingerprints() != deployment.journal.document['completed'].get('split-transport'):
        raise InstallError('Pinned SSH transport changed before dependency transfer')
    sources = _source_bytes(deployment, helpers)
    asset = kit.asset(ROLE)
    if asset.format != 'tar.gz' or not 0 < asset.size <= 8 * 1024**3:
        raise InstallError('Remote dependency asset is unsupported or oversized')
    work = Path(tempfile.gettempdir()) / ('iris-split-transfer-' + secrets.token_hex(16))
    with offline_inputs._new_directory(work, remove=True):
        archive = kit.copy_asset(ROLE, work / 'closure.tar.gz')
        offline_inputs.inspect_dependency_archive(archive,
            expected_manifest_sha256=asset.dependency_manifest_sha256)
        rows = [{'name': name, 'size': len(sources[name]), 'sha256': helpers[name]} for name in SOURCES]
        rows.append({'name': 'closure.tar.gz', 'size': asset.size, 'sha256': asset.sha256})
        raw = _json({'schema': 'iris-split-dependency-wire-v1', 'request': request, 'files': rows})
        if len(raw) > MAX_JSON:
            raise InstallError('Remote dependency request exceeds its size limit')
        with tempfile.TemporaryFile() as wire:
            wire.write(len(raw).to_bytes(8, 'big')); wire.write(raw)
            for name in SOURCES:
                wire.write(sources[name])
            fd, before = release_kit._open(archive, asset.size)
            try:
                digest, size = release_kit._hash(fd, asset.size, wire)
                if (digest != asset.sha256 or size != asset.size
                        or release_kit._identity(before) != release_kit._identity(os.fstat(fd))):
                    raise InstallError('Dependency asset changed before SSH transfer')
            finally:
                os.close(fd)
            wire.seek(0)
            command = ('sudo -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin '
                       'DEBIAN_FRONTEND=noninteractive python3 -I -B -c ' + shlex.quote(BOOTSTRAP)
                       + ' ' + hashlib.sha256(raw).hexdigest())
            if deployment.transport_fingerprints() != deployment.journal.document['completed'].get('split-transport'):
                raise InstallError('Pinned SSH transport changed before dependency execution')
            return _run_remote(deployment.ssh_command(command), deployment.env, wire)


def _remote_identity(request):
    """Read-only remote custody checks before any resolver or package operation."""
    from . import offline_dependencies as dependencies, ubuntu
    if os.geteuid() != 0:
        raise InstallError('Remote dependency validation requires root sudo')
    ubuntu.check_platform()
    root = release_kit._path(Path(request['root']))
    if len(root.parts) < 4:
        raise InstallError('Remote Console custody must be a dedicated directory')
    descriptor = release_kit._protected_directory(root)
    os.close(descriptor)
    marker = root / 'owner.json'
    info = marker.lstat()
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
        raise InstallError('Remote Console ownership marker is unsafe')
    if release_kit._json(regular_bytes(marker, 16384)) != {
            'instance_id': request['identity'], 'project': request['project']}:
        raise InstallError('Remote Console ownership changed before dependency validation')
    docker = shutil.which('docker', path=dependencies.ENV['PATH'])
    if docker:
        for kind in ('container', 'volume', 'network'):
            args = [docker, kind, 'ls', '-q'] + (['-a'] if kind == 'container' else [])
            identifiers = dependencies._run([*args, '--filter', 'label=com.docker.compose.project=' + request['project']]).split()
            for identifier in identifiers:
                for item in json.loads(dependencies._run([docker, kind, 'inspect', identifier])):
                    labels = item.get('Config', {}).get('Labels', {}) if kind == 'container' else item.get('Labels', {})
                    if not labels or labels.get('com.cisco.iris.installer') != request['identity']:
                        raise InstallError('Unfamiliar remote Console Docker resource')
    machine = regular_bytes(Path('/etc/machine-id'), 128)
    if not re.fullmatch(rb'[0-9a-f]{32}\n?', machine):
        raise InstallError('Remote host machine identity is unavailable')
    return hashlib.sha256(machine.rstrip(b'\n')).hexdigest()


def perform_remote(archive, request):
    """Run only after the fixed SSH bootstrap has verified every input byte."""
    from . import offline_dependencies as dependencies, prebuilt_dependencies as plans
    common = {'action', 'root', 'identity', 'project', 'dependency_manifest_sha256'}
    action = request.get('action') if isinstance(request, dict) else None
    if action not in ('plan', 'apply'):
        raise InstallError('Unknown remote dependency operation')
    _fields(request, common | ({'host', 'plan', 'evidence', 'phase', 'accepted_changes'} if action == 'apply' else set()))
    for name in ('identity', 'project'):
        if not isinstance(request[name], str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', request[name]):
            raise InstallError('Remote dependency owner identity is invalid')
    release_kit._sha(request['dependency_manifest_sha256'])
    host = _remote_identity(request)
    if action == 'apply' and (request['accepted_changes'] is not True
            or request['phase'] not in ('accepted', 'complete') or request['host'] != host):
        raise InstallError('Remote host or accepted dependency authority changed')
    if action == 'apply' and (not isinstance(request['plan'], dict)
            or request['plan'].get('required_roots') != sorted(REMOTE_ROOTS)):
        raise InstallError('Remote dependency plan has a different Console package scope')
    destination = Path(archive).parent / 'payload'
    offline_inputs.inspect_dependency_archive(archive,
        expected_manifest_sha256=request['dependency_manifest_sha256'], destination=destination)
    # No keyring is transported: the default keyring belongs to this host.
    with dependencies.validate_closure(destination, request['dependency_manifest_sha256']) as closure:
        if action == 'plan':
            plan = dependencies.plan_dependencies(closure, required_roots=REMOTE_ROOTS)
            return {'schema': PLAN, 'host': host, 'plan': plan,
                    'evidence': plans.evidence_for_plan(plan)}
        if request['phase'] == 'complete':
            result = plans.validate_completed_plan(closure, request['plan'], request['evidence'])
        else:
            result = plans.apply_accepted_plan(closure, request['plan'], request['evidence'], accept_changes=True)
        return {'schema': DONE, 'host': host, **result}


def provision(deployment):
    """Persist the exact accepted remote plan before invoking its apply seam."""
    from .prebuilt_install import _kit
    kit = _kit(deployment)
    if kit.profile != ROLE:
        raise InstallError('Remote offline provisioning requires the dependency profile')
    helpers = _helper_hashes(deployment)
    config, document = deployment.config, deployment.journal.document
    authority = {'schema': 'iris-split-dependency-authority-v1', 'kit': kit.receipt(),
        'identity': document['id'], 'project': config['instance'], 'root': config['console_state_dir'],
        'endpoint': {name: config[name] for name in ('console_ssh_host', 'console_ssh_port', 'console_ssh_user')},
        'transport': deployment.transport_fingerprints(), 'helpers': helpers,
        'dependency_manifest_sha256': kit.asset(ROLE).dependency_manifest_sha256}
    if authority['transport'] != document['completed'].get('split-transport'):
        raise InstallError('Remote dependency transport differs from its recorded authority')
    request = {name: authority[name] for name in ('root', 'identity', 'project', 'dependency_manifest_sha256')}
    if RECORD not in document:
        if (set(document['completed']) != {'prepared', 'split-prepared', 'split-transport'}
                or document.get('state') != 'split-prepared'):
            raise InstallError('Remote dependency acceptance is missing after deployment progressed; refusing a new plan')
        local = document.get('dependency_provisioning')
        if (not isinstance(local, dict) or local.get('schema') != 'iris-prebuilt-dependencies-v1'
                or local.get('phase') != 'complete' or local.get('accepted_changes') is not True
                or local.get('kit') != kit.receipt() or config.get('target') != 'docker-split'):
            raise InstallError('Remote dependency planning requires the accepted split installation')
        answer = _exchange(deployment, kit, dict(request, action='plan'), helpers)
        _fields(answer, {'schema', 'host', 'plan', 'evidence'})
        if answer['schema'] != PLAN:
            raise InstallError('Remote dependency plan response is invalid')
        release_kit._sha(answer['host'])
        record = {'schema': 'iris-split-dependency-provisioning-v1', 'authority': authority,
                  'accepted_changes': True, 'phase': 'accepted',
                  **{name: answer[name] for name in ('host', 'plan', 'evidence')}}
        document[RECORD] = record
        deployment.journal.save()
    record = document[RECORD]
    keys = {'schema', 'authority', 'accepted_changes', 'phase', 'host', 'plan', 'evidence'}
    _fields(record, keys | ({'completion'} if isinstance(record, dict) and record.get('phase') == 'complete' else set()))
    if (record['schema'] != 'iris-split-dependency-provisioning-v1'
            or _json(record['authority']) != _json(authority) or record['accepted_changes'] is not True
            or record['phase'] not in ('accepted', 'complete')):
        raise InstallError('Recorded remote dependency authority changed')
    release_kit._sha(record['host'])
    if record['phase'] == 'complete':
        _fields(record['completion'], {'schema', 'host', 'status_sha256'})
        if record['completion']['schema'] != DONE or record['completion']['host'] != record['host']:
            raise InstallError('Recorded remote dependency completion is invalid')
        release_kit._sha(record['completion']['status_sha256'])
    answer = _exchange(deployment, kit, dict(request, action='apply',
        **{name: record[name] for name in ('host', 'plan', 'evidence', 'phase', 'accepted_changes')}), helpers)
    _fields(answer, {'schema', 'host', 'status_sha256'})
    if answer['schema'] != DONE or answer['host'] != record['host']:
        raise InstallError('Remote dependency completion belongs to a different host')
    release_kit._sha(answer['status_sha256'])
    if record['phase'] == 'complete':
        # Later operator/security updates are allowed when current read-only
        # validation needs no package changes. Keep the original apply receipt.
        return
    document[RECORD] = {**record, 'phase': 'complete', 'completion': answer}
    deployment.journal.save()
