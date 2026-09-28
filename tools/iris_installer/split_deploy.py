# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Owned split-Docker deployment with a pinned, noninteractive SSH transport.

The server and all build inputs stay local. Only the Console image, its browser
certificate, the tier bearer credential and public management CA cross hosts.
"""

import base64
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import subprocess
import tempfile

from .deploy import DockerInstall, OWNER_CLAIM, PRODUCTION_REVIEW, digest, run
from .state import InstallError, atomic_write, regular_bytes


SPLIT_FIELDS = {
    'console_ssh_host', 'console_ssh_user', 'console_ssh_port',
    'console_ssh_key', 'console_known_hosts', 'console_state_dir', 'management_bind',
}


def validate_split_config(config):
    """Validate the transport separately from the common deployment fields."""
    if not SPLIT_FIELDS.issubset(config):
        raise InstallError('Split Docker requires explicit SSH transport and Console custody settings')
    base = {'target', 'instance', 'host', 'console_bind', 'console_port', 'recovery_recipient', 'peer_tls'}
    if set(config) != base | SPLIT_FIELDS:
        raise InstallError('Unexpected split deployment configuration fields')
    for field in ('console_ssh_host', 'management_bind'):
        try:
            address = ipaddress.IPv4Address(config[field])
        except (ValueError, TypeError):
            raise InstallError(field + ' must be a concrete IPv4 address') from None
        if address.is_unspecified or address.is_multicast or address.is_loopback:
            raise InstallError(field + ' must be a concrete remote address')
    if not isinstance(config['console_ssh_user'], str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', config['console_ssh_user']):
        raise InstallError('Invalid Console SSH user')
    if type(config['console_ssh_port']) is not int or not 1 <= config['console_ssh_port'] <= 65535:
        raise InstallError('Invalid Console SSH port')
    root = config['console_state_dir']
    if (not isinstance(root, str) or not re.fullmatch(r'/[A-Za-z0-9_/-]+', root)
            or str(Path(root)) != root or '..' in Path(root).parts
            or len(Path(root).parts) < 4):
        raise InstallError('Choose a dedicated absolute Console state directory below an existing parent')
    for field in ('console_ssh_key', 'console_known_hosts'):
        path = Path(config[field])
        if not path.is_absolute() or path.resolve() != path:
            raise InstallError(field + ' must be an absolute non-symlink path')
        try:
            info = path.lstat()
            data = regular_bytes(path, 1024 * 1024)
        except OSError:
            raise InstallError(field + ' is unavailable') from None
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or not data:
            raise InstallError(field + ' must be a nonempty root-owned regular file')
        if info.st_mode & (0o077 if field == 'console_ssh_key' else 0o022):
            raise InstallError(field + ' has unsafe permissions')
    if config['management_bind'] != config['host']:
        raise InstallError('Management bind must match the device-facing host certificate address')


def preflight(config, runner=run):
    """Check local listeners and remote custody/port without claiming resources."""
    validate_split_config(config)
    for port in (6969, 8443, 8000, 6881, 9101, 9443):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind((config['host'], port))
            except OSError:
                raise InstallError('Server listener is unavailable; no deployment was created') from None
    code = r'''
import json,os,pathlib,platform,shutil,socket,subprocess,sys
r=json.load(sys.stdin); root=pathlib.Path(r['console_state_dir'])
if os.geteuid()!=0: raise RuntimeError('Root sudo is required')
for path in [*reversed(root.parents),root]:
 if path.is_symlink(): raise RuntimeError('Unsafe Console custody path')
 if path.exists() and (path.stat().st_uid!=0 or path.stat().st_mode&0o022): raise RuntimeError('Unsafe Console parent')
if root.exists() or not root.parent.is_dir(): raise RuntimeError('Console custody must be new with an existing parent')
with socket.socket() as sock: sock.bind((r['console_bind'],r['console_port']))
if shutil.which('docker'):
 for kind in ('container','volume','network'):
  args=['docker',kind,'ls','-q']+(['-a'] if kind=='container' else [])
  result=subprocess.run(args+['--filter','label=com.docker.compose.project='+r['instance']],stdout=subprocess.PIPE,check=True)
  if result.stdout.strip(): raise RuntimeError('Console project already exists')
'''
    # Reuse the sole SSH construction path without constructing a deployment.
    transport = object.__new__(SplitDockerInstall)
    transport.config = config
    command = 'sudo -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin python3 -I -B -c ' + shlex.quote(code)
    runner(transport.ssh_command(command), input=json.dumps(config).encode(), capture=True, timeout=60)


# One fixed program, with a bounded JSON request on stdin. Neither credentials
# nor caller-supplied commands are interpolated into the remote shell command.
REMOTE_PROGRAM = r'''
import base64, hashlib, json, os, pathlib, platform, stat, subprocess, sys, tempfile
r=json.loads(sys.stdin.buffer.read(8*1024*1024+1))
root=pathlib.Path(r['root']); identity=r['identity']; project=r['project']
def run(args, data=None):
 p=subprocess.run(args,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
 if p.returncode: raise RuntimeError('Remote operation failed: '+args[0])
 return p.stdout
def check_path(path):
 for item in [*reversed(path.parents),path]:
  if item.is_symlink(): raise RuntimeError('Symlink in Console custody path')
  if item.exists():
   s=item.stat()
   if s.st_uid!=0 or s.st_mode&0o022: raise RuntimeError('Unsafe Console custody ancestor')
check_path(root)
marker=root/'owner.json'
if r['action']=='claim':
 if root.exists():
  if not marker.is_file() or marker.is_symlink() or json.loads(marker.read_bytes())!={'instance_id':identity,'project':project}:
   raise RuntimeError('Console directory is not owned by this installation')
 else:
  root.mkdir(mode=0o750)
  marker.write_text(json.dumps({'instance_id':identity,'project':project})); marker.chmod(0o600)
  os.chown(root,0,10001)
else:
 if not marker.is_file() or marker.is_symlink() or json.loads(marker.read_bytes())!={'instance_id':identity,'project':project}:
  raise RuntimeError('Console ownership could not be verified')
def owned():
 for kind in ('container','volume','network'):
  args=['docker',kind,'ls','-q']+(['-a'] if kind=='container' else [])
  ids=run(args+['--filter','label=com.docker.compose.project='+project]).decode().split()
  for rid in ids:
   for obj in json.loads(run(['docker',kind,'inspect',rid])):
    labels=obj.get('Config',{}).get('Labels',{}) if kind=='container' else obj.get('Labels',{})
    if not labels or labels.get('com.cisco.iris.installer')!=identity:
     raise RuntimeError('Unfamiliar Console Docker resource')
def write(name,data,mode):
 path=root/name
 if path.is_symlink(): raise RuntimeError('Unsafe Console file')
 fd,tmp=tempfile.mkstemp(prefix='.iris-',dir=root)
 try:
  os.fchmod(fd,mode); os.fchown(fd,0,10001)
  with os.fdopen(fd,'wb') as f: f.write(data); f.flush(); os.fsync(f.fileno())
  os.replace(tmp,path)
  fd=os.open(root,os.O_DIRECTORY); os.fsync(fd); os.close(fd)
 finally:
  if os.path.exists(tmp): os.unlink(tmp)
action=r['action']
if action=='claim': pass
elif action=='provision':
 release=dict(line.rstrip().split('=',1) for line in pathlib.Path('/etc/os-release').read_text().splitlines() if '=' in line)
 if release.get('ID','').strip('"')!='ubuntu' or release.get('VERSION_ID','').strip('"')!='24.04' or platform.machine()!='x86_64':
  raise RuntimeError('Console requires Ubuntu 24.04 amd64')
 packages=[]
 import shutil
 if not shutil.which('openssl'): packages.append('openssl')
 if not shutil.which('docker'): packages+=['docker.io','docker-compose-v2']
 elif subprocess.run(['docker','compose','version'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:
  for provider,pkg in [('docker.io','docker-compose-v2'),('docker-ce','docker-compose-plugin')]:
   if subprocess.run(['dpkg-query','--status',provider],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:
    packages.append(pkg); break
  else: raise RuntimeError('Unrecognized Docker provider')
 if packages:
  run(['apt-get','update']); run(['apt-get','install','--no-remove','-y',*packages])
 run(['docker','info']); run(['docker','compose','version']); owned()
elif action=='inspect':
 owned(); sys.stdout.buffer.write(run(['docker','image','inspect',r['image'],'--format','{{.Id}}']))
elif action=='container':
 owned(); record,=json.loads(run(['docker','container','inspect',project+'-console']))
 if record.get('Config',{}).get('Labels',{}).get('com.cisco.iris.installer')!=identity or record['Image']!=r['image']:
  raise RuntimeError('Console image or ownership changed')
 for mount in record['Mounts']:
  if mount['Type'] not in ('bind','tmpfs') or (mount['Type']=='bind' and (mount['Source']!=str(root) or mount.get('RW',True))):
   raise RuntimeError('Unexpected Console mount')
 for identifier in run(['docker','container','ls','-aq']).decode().split():
  other,=json.loads(run(['docker','container','inspect',identifier]))
  if other['Id']==record['Id']: continue
  for mount in other['Mounts']:
   source=pathlib.Path(mount.get('Source','/nonexistent'))
   if mount.get('RW',True) and (source==root or root in source.parents or source in root.parents):
    raise RuntimeError('Another container can modify Console custody')
 sys.stdout.write(json.dumps({'id':record['Id'],'service':'console','remote':True,'running':record['State']['Running'],'state':record['State']}))
elif action=='write':
 owned()
 allowed={'compose.json','current.json','previous.json','ca.pem','tls.crt','tls.key'}
 for name,value in r['files'].items():
  if name not in allowed: raise RuntimeError('File is outside Console custody')
  write(name,base64.b64decode(value,validate=True),0o640 if name in ('current.json','previous.json','tls.key') else 0o644)
elif action=='browser':
 owned()
 key=root/'tls.key'; cert=root/'tls.crt'
 if key.is_symlink() or cert.is_symlink(): raise RuntimeError('Unsafe browser certificate path')
 if key.exists()!=cert.exists(): raise RuntimeError('Incomplete browser certificate; preserve custody for recovery')
 if not key.exists():
  run(['openssl','req','-x509','-newkey','rsa:3072','-nodes','-days','90','-subj','/CN='+r['host'],'-addext','subjectAltName=IP:'+r['host'],'-keyout',str(key),'-out',str(cert)])
  key.chmod(0o640); os.chown(key,0,10001); cert.chmod(0o644)
 sys.stdout.buffer.write(cert.read_bytes())
elif action=='compose':
 owned()
 spec=root/'compose.json'
 if spec.is_symlink() or hashlib.sha256(spec.read_bytes()).hexdigest()!=r['digest']:
  raise RuntimeError('Console configuration changed')
 sys.stdout.buffer.write(run(['docker','compose','-p',project,'-f',str(spec),*r['args']],base64.b64decode(r['input']) if r.get('input') else None))
elif action=='snapshot':
 owned(); result={}
 for name in ('current.json','previous.json','ca.pem','tls.crt','tls.key'):
  path=root/name
  if path.is_symlink(): raise RuntimeError('Unsafe Console custody file')
  if path.exists(): result[name]=base64.b64encode(path.read_bytes()).decode()
 sys.stdout.write(json.dumps(result))
else: raise RuntimeError('Unknown Console operation')
'''


class SplitDockerInstall(DockerInstall):
    """Local server plus separately owned, SSH-managed remote Console."""

    def __init__(self, journal, runner=run):
        super().__init__(journal, runner)
        validate_split_config(self.config)
        self.console_file = self.base / 'console-compose.json'
        self.console_build_file = self.base / 'console-build.json'

    def lifecycle_capabilities(self):
        return ['management-tls', 'device-tls', 'peer-ca', 'instruction-roots',
                'age-identity', 'age-recovery', 'seeder-announce']

    def ssh_command(self, remote_command):
        c = self.config
        return ['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                '-o', 'StrictHostKeyChecking=yes', '-o', 'GlobalKnownHostsFile=/dev/null',
                '-o', 'UserKnownHostsFile=' + c['console_known_hosts'],
                '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
                '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes',
                '-o', 'ConnectTimeout=15', '-i', c['console_ssh_key'],
                '-p', str(c['console_ssh_port']), c['console_ssh_user'] + '@' + c['console_ssh_host'],
                remote_command]

    def remote(self, action, *, timeout=7200, **values):
        expected = self.journal.document['completed'].get('split-transport')
        if expected is not None and self.transport_fingerprints() != expected:
            raise InstallError('Pinned SSH transport custody changed; remote operation refused')
        payload = dict(action=action, root=self.config['console_state_dir'],
                       identity=self.journal.document['id'], project=self.config['instance'], **values)
        command = 'sudo -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin DEBIAN_FRONTEND=noninteractive python3 -I -B -c ' + shlex.quote(REMOTE_PROGRAM)
        return self.command(self.ssh_command(command), input=json.dumps(payload).encode(), capture=True, timeout=timeout)

    def transport_fingerprints(self):
        validate_split_config(self.config)
        return {field: digest(self.config[field]) for field in ('console_ssh_key', 'console_known_hosts')}

    def remote_console(self, *args, **kwargs):
        payload = kwargs.pop('input', None)
        expected = self.journal.document['completed'].get('console-prepared')
        actual = digest(self.console_file)
        if expected is not None and actual != expected:
            raise InstallError('Owned Console configuration changed')
        # All calls originate in the privileged local adapter, never a browser.
        result = self.remote('compose', args=[str(a) for a in args], digest=actual,
                             timeout=kwargs.get('timeout', 7200),
                             input=base64.b64encode(payload).decode() if payload else None)
        return result if kwargs.get('capture') else b''

    def compose(self, *args, **kwargs):
        if args and args[0] in ('stop', 'start', 'up', 'restart', 'down'):
            selected = {arg for arg in args[1:] if arg in ('iris', 'console')}
            if selected == {'iris', 'console'} or not selected:
                local_args = tuple(arg for arg in args if arg != 'console')
                remote_args = tuple(arg for arg in args if arg != 'iris')
                if not selected and args[0] != 'down':
                    local_args += ('iris',)
                    remote_args += ('console',)
                if args[0] in ('stop', 'down'):
                    remote = self.remote_console(*remote_args, **kwargs)
                    return remote + self.compose(*local_args, **kwargs) if args[0] != 'down' else remote + super().compose(*local_args, **kwargs)
                local = self.compose(*local_args, **kwargs)
                return local + self.remote_console(*remote_args, **kwargs)
        if args and args[-1] == 'console':
            return self.remote_console(*args, **kwargs)
        if len(args) > 2 and args[0] == 'exec' and args[2] == 'console':
            return self.remote_console(*args, **kwargs)
        if getattr(self, '_runtime_images', None):
            spec = json.loads(regular_bytes(self.compose_file))
            for service in spec['services'].values():
                service['image'] = self._runtime_images[service['image']]
                service.pop('build', None)
            with tempfile.TemporaryDirectory(prefix='split-runtime-', dir=self.base) as directory:
                path = Path(directory) / 'compose.json'
                atomic_write(path, json.dumps(spec).encode())
                return self.command(['docker', 'compose', '-p', self.config['instance'], '-f', path, *args], **kwargs)
        return super().compose(*args, **kwargs)

    def pin_runtime(self):
        images = self.journal.document['completed'].get('images', {})
        if not images:
            raise InstallError('Recorded deployment image identities are required')
        for tag, expected in images.items():
            actual = self.command(['docker', 'image', 'inspect', tag, '--format', '{{.Id}}'], capture=True).decode().strip()
            if actual != expected:
                raise InstallError('Deployment image changed; maintenance refused')
        expected = self.journal.document['completed']['console-image']
        if self.remote('inspect', image=expected).decode().strip() != expected:
            raise InstallError('Remote Console image changed; maintenance refused')
        self._runtime_images = dict(images)

    def capture_plan(self):
        from .backup import docker_capture_plan
        sources, volumes, containers = docker_capture_plan(self, services=('iris',))
        console = self.remote_container()
        containers.insert(0, console)
        sources['console-deployment'] = self.console_file
        sources['console-build'] = self.console_build_file
        return sources, volumes, containers

    def remote_container(self):
        return json.loads(self.remote('container', image=self.journal.document['completed']['console-image']))

    def stop_writers(self, containers, *, recovering_clean_operation=False):
        for container in containers:
            if container.get('remote'):
                record = self.remote_container()
                if record['id'] != container['id']:
                    raise InstallError('Remote Console identity changed before maintenance')
                self.remote_console('stop', '--timeout', '120', 'console')
                record = self.remote_container()
            else:
                self.command(['docker', 'container', 'stop', '--time', '120', container['id']])
                record, = json.loads(self.command(['docker', 'container', 'inspect', container['id']], capture=True))
                record = {'state': record['State']}
            state = record['state']
            if state['Running'] or (not recovering_clean_operation and (state.get('OOMKilled') or state.get('ExitCode') not in (0, 143))):
                raise InstallError('Split deployment writers did not stop cleanly')

    def restart_writer(self, container):
        if container.get('remote'):
            # The bootstrap management certificate is reconstructed when the
            # server starts. Refresh its public trust and current token pair
            # before the remote Console attempts its authenticated startup.
            self.sync_console_credentials()
            self.remote_console('up', '-d', '--no-build', '--wait', '--wait-timeout', '180', 'console')
            self.verify_console_management()
        else:
            self.compose('up', '-d', '--no-build', '--wait', '--wait-timeout', '180', 'iris')

    def assert_writers_stopped(self):
        remote = self.remote_container()
        local, = json.loads(self.command(['docker', 'container', 'inspect', self.config['instance'] + '-server'], capture=True))
        transaction = getattr(self, 'credential_transaction', None)
        admitted_recovery = (getattr(self, 'credential_recovery', False) is True
            and transaction is not None and transaction.record.get('initial_clean_stop') is True)
        for state in (remote['state'], local['State']):
            if state['Running'] or (not admitted_recovery and (state.get('OOMKilled') or state.get('ExitCode') not in (0, 143))):
                raise InstallError('All split deployment writers must remain cleanly stopped')

    def backup_export_images(self, path):
        images = set(self.journal.document['completed']['images'].values())
        images.add(self.journal.document['completed']['console-image'])
        self.command(['docker', 'image', 'save', '-o', path, *sorted(images)])

    def capture_backup_extras(self, sources):
        self.assert_writers_stopped()
        # Remote custody is encrypted before touching server disk. The server
        # identity never leaves this host, including during recovery export.
        recipient = self.command(['age-keygen', '-y', self.base / 'age.txt'], capture=True).decode().strip()
        encrypted = self.command(['age', '-r', recipient, '-r', self.config['recovery_recipient']],
                                 input=self.console_custody_snapshot(), capture=True)
        path = self.base / 'remote-console-custody.age'
        atomic_write(path, encrypted)
        sources['remote-console-custody'] = path

    def before_console_start(self):
        self.sync_console_credentials()

    def prepare(self):
        completed = self.journal.document['completed']
        if 'split-prepared' in completed:
            if digest(self.compose_file) != completed['prepared'] or digest(self.console_build_file) != completed['split-prepared']:
                raise InstallError('Split deployment configuration changed')
            return
        super().prepare()
        both = json.loads(regular_bytes(self.compose_file))
        console = both['services'].pop('console')
        both['services']['iris'].setdefault('environment', {})['IRIS_INSTALLER_TARGET'] = 'docker-split'
        both['services']['iris'].setdefault('ports', []).append({
            'target': 9443, 'published': '9443', 'host_ip': self.config['management_bind'], 'protocol': 'tcp'})
        local_build = {'name': self.config['instance'], 'services': {'console': copy.deepcopy(console)}}
        local_build['services']['console'].pop('depends_on', None)
        local_build['services']['console']['volumes'] = []
        atomic_write(self.console_build_file, json.dumps(local_build, sort_keys=True).encode())
        atomic_write(self.compose_file, json.dumps(both, sort_keys=True, indent=2).encode())
        self.journal.document['completed']['prepared'] = digest(self.compose_file)
        self.journal.document['completed']['split-transport'] = self.transport_fingerprints()
        self.journal.checkpoint('split-prepared', digest(self.console_build_file))
        self.remote('claim')
        self.remote('provision')

    def verify_resource_ownership(self):
        super().verify_resource_ownership()
        if 'split-prepared' in self.journal.document['completed']:
            self.remote('claim')
            self.remote('provision')

    def _transfer_image(self, image):
        """Stream docker save directly through SSH; no unbounded RAM archive."""
        if self.transport_fingerprints() != self.journal.document['completed'].get('split-transport'):
            raise InstallError('Pinned SSH transport custody changed; image transfer refused')
        remote = self.ssh_command('sudo -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin docker image load')
        save = subprocess.Popen(['docker', 'image', 'save', image], env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            loaded = subprocess.run(remote, env=self.env, stdin=save.stdout,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1800)
            save.stdout.close()
            result = save.wait(timeout=60)
            if loaded.returncode or result:
                raise InstallError('Console image transfer failed; local image and journal retained')
        except (subprocess.TimeoutExpired, OSError):
            raise InstallError('Console image transfer did not complete') from None
        finally:
            if save.poll() is None:
                save.kill(); save.wait()

    def build(self):
        super().build()
        saved = self.journal.document['completed'].get('console-image')
        image = json.loads(regular_bytes(self.console_build_file))['services']['console']['image']
        if not saved:
            self.command(['docker', 'compose', '-p', self.config['instance'], '-f', self.console_build_file, 'build', '--pull'])
            saved = self.command(['docker', 'image', 'inspect', image, '--format', '{{.Id}}'], capture=True).decode().strip()
            if not re.fullmatch(r'sha256:[0-9a-f]{64}', saved):
                raise InstallError('Invalid Console image identity')
            self.journal.checkpoint('console-image', saved)
        actual = self.command(['docker', 'image', 'inspect', image, '--format', '{{.Id}}'], capture=True).decode().strip()
        if actual != saved:
            raise InstallError('Console build image changed')
        images = dict(self.journal.document['completed']['images'])
        images[image] = saved
        self.journal.checkpoint('images', images)
        self._transfer_image(saved)
        if self.remote('inspect', image=saved).decode().strip() != saved:
            raise InstallError('Remote Console image verification failed')
        spec = json.loads(regular_bytes(self.console_build_file))['services']['console']
        spec.pop('build', None); spec['image'] = saved
        spec['environment'].update(IRIS_MANAGEMENT_API_URL='https://' + self.config['management_bind'] + ':9443',
                                   IRIS_GUI_DEFAULT_CERT='/run/iris-console-custody/tls.crt',
                                   IRIS_GUI_DEFAULT_KEY='/run/iris-console-custody/tls.key',
                                   IRIS_MANAGEMENT_API_TOKEN_FILE='/run/iris-console-custody/current.json',
                                   IRIS_MANAGEMENT_API_PREVIOUS_TOKEN_FILE='/run/iris-console-custody/previous.json',
                                   IRIS_MANAGEMENT_API_CA='/run/iris-console-custody/ca.pem')
        spec['volumes'] = [{'type': 'bind', 'source': self.config['console_state_dir'],
                            'target': '/run/iris-console-custody', 'read_only': True,
                            'bind': {'create_host_path': False}}]
        result = {'name': self.config['instance'], 'services': {'console': spec},
                  'networks': {'default': {'labels': {'com.cisco.iris.installer': self.journal.document['id']}}}}
        data = json.dumps(result, sort_keys=True, indent=2).encode()
        atomic_write(self.console_file, data)
        self.remote('write', files={'compose.json': base64.b64encode(data).decode()})
        self.journal.checkpoint('console-prepared', digest(self.console_file))
        self._runtime_images = dict(self.journal.document['completed']['images'])

    def sync_console_credentials(self):
        files = json.loads(self.python(
            "import base64,json,pathlib; p=pathlib.Path('/run/iris-tier'); "
            "v={n:base64.b64encode((p/n).read_bytes()).decode() for n in ('current.json','previous.json') if (p/n).exists()}; "
            "v['ca.pem']=base64.b64encode(pathlib.Path('/run/iris-management-ca/ca.pem').read_bytes()).decode(); print(json.dumps(v))"))
        if set(files) - {'current.json', 'previous.json', 'ca.pem'} or not {'current.json', 'ca.pem'}.issubset(files):
            raise InstallError('Invalid public management export')
        # An empty previous token removes obsolete authority rather than leaving
        # a previously valid credential on the other host indefinitely.
        files.setdefault('previous.json', '')
        self.remote('write', files=files)

    def console_custody_snapshot(self):
        """Private in-memory payload; caller must encrypt before persistence."""
        return self.remote('snapshot')

    def restore_console_custody(self, payload):
        files = json.loads(payload)
        if not isinstance(files, dict) or set(files) - {'current.json', 'previous.json', 'ca.pem', 'tls.crt', 'tls.key'}:
            raise InstallError('Invalid Console custody backup')
        self.remote('write', files=files)

    def verify_console_management(self, expected_token=None):
        code = '''import os,sys,ssl,http.client,hashlib,json
sys.path.insert(0,'/opt/iris/server')
import tier_auth
from urllib.parse import urlsplit
u=urlsplit(os.environ['IRIS_MANAGEMENT_API_URL'])
c=http.client.HTTPSConnection(u.hostname,u.port or 443,timeout=20,context=ssl.create_default_context(cafile=os.environ['IRIS_MANAGEMENT_API_CA']))
t,_=tier_auth.load_pair(os.environ['IRIS_MANAGEMENT_API_TOKEN_FILE'])
c.connect(); fingerprint=hashlib.sha256(c.sock.getpeercert(binary_form=True)).hexdigest()
c.request('GET','/internal/v1/console-certificate',headers={'Authorization':'Bearer '+t.decode(),'X-IRIS-Default-Certificate':'available'})
r=c.getresponse()
if r.status not in (200,204): raise RuntimeError('authentication')
c.close(); print(json.dumps({'management_https':'verified','certificate_sha256':fingerprint,'current_token_sha256':hashlib.sha256(t).hexdigest()}))
'''
        answer = json.loads(self.remote_console('exec', '-T', 'console', 'python3', '-I', '-B', '-c', code, capture=True))
        if answer.get('management_https') != 'verified' or not re.fullmatch(r'[0-9a-f]{64}', answer.get('certificate_sha256', '')):
            raise InstallError('Remote Console could not authenticate the management connection')
        token = answer.pop('current_token_sha256', None)
        if expected_token is not None and token != expected_token:
            raise InstallError('Remote Console is not using the approved replacement credential')
        return answer

    def sync_management_operation(self, operation_id):
        from .management_sync import validate_operation
        authority = validate_operation(self, operation_id)
        self.verify_resource_ownership()
        self.remote_container()  # Exact owned image and custody mounts.
        self.sync_console_credentials()
        self.verify_console_management(expected_token=authority['current_sha256'])
        if validate_operation(self, operation_id) != authority:
            raise InstallError('Management credential authority changed during publication')
        return dict(authority, consumers_verified=1)

    lifecycle_consumer_proof = verify_console_management

    def finish(self):
        self.sync_console_credentials()
        certificate = self.remote('browser', host=self.config['console_bind'])
        atomic_write(self.base / 'requests/console-cert.pem', certificate, 0o644)
        self.remote_console('up', '-d', '--no-build', '--wait', '--wait-timeout', '180', 'console')
        self.verify_console_management()
        claimed = self.python("import gui_auth,secrets_store,os; print(bool(gui_auth.get_admin(secrets_store.load(os.environ['IRIS_SECRETS']))))").strip()
        if claimed not in (b'True', b'False'):
            raise InstallError('Cannot determine Console ownership; no account was changed')
        state = 'OWNER_CLAIM_REQUIRED' if claimed == b'False' else 'PRODUCTION_REVIEW_REQUIRED'
        self.journal.pause(state)
        print(state + ': https://' + self.config['console_bind'] + ':' + str(self.config['console_port']) + '/')
        print('Verify the exported public Console certificate before sign-in. No administrator was created or logged in.')
        return OWNER_CLAIM if claimed == b'False' else PRODUCTION_REVIEW
