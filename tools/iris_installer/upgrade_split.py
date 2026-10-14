# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Split-Console boundaries within the existing forward-only upgrade.

The fixed SSH program extends the existing ownership, transport and mount
checks. It never transfers server secrets or grants an arbitrary remote command.
"""

import base64
import copy
import hashlib
import json

from . import upgrade_plan as plan
from .state import atomic_write, regular_bytes


REMOTE_EXTENSION = r'''
def upgrade_file(path):
 info=path.lstat()
 if (path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid!=0
     or info.st_nlink!=1 or info.st_mode&0o022):
  raise RuntimeError('Remote upgrade input custody changed')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as stream:
  held=os.fstat(stream.fileno()); data=stream.read(8*1024*1024+1)
  identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_uid,s.st_gid,s.st_mode,s.st_nlink)
  if identity(held)!=identity(os.fstat(stream.fileno())) or identity(held)!=identity(path.lstat()) or len(data)>8*1024*1024:
   raise RuntimeError('Remote upgrade input changed while reading')
 return data
def upgrade_credentials():
 answer={}
 for name in ('current.json','previous.json','ca.pem','tls.crt','tls.key'):
  path=root/name
  if path.exists() or path.is_symlink():
   data=upgrade_file(path); info=path.lstat()
   if name in ('current.json','previous.json','tls.key') and info.st_mode&0o007:
    raise RuntimeError('Remote private credentials became public')
   answer[name]={'sha256':hashlib.sha256(data).hexdigest(),'device':info.st_dev,
                'inode':info.st_ino,'mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid,'gid':info.st_gid}
 if not {'current.json','ca.pem','tls.crt','tls.key'}<=set(answer):
  raise RuntimeError('Remote Console credentials are incomplete')
 return answer
def upgrade_canonical(value):
 return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def upgrade_record(value):
 if (not isinstance(value,dict) or not {'operation_id','contract_sha256','phase'}<=set(value)
     or set(value)-{'operation_id','contract_sha256','phase','publication_admitted','start_intent','container_id','ca_intent'}
     or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',str(value.get('operation_id')))
     or not re.fullmatch(r'[0-9a-f]{64}',str(value.get('contract_sha256')))
     or value.get('phase') not in ('fencing','fenced','published','started','upgraded')
     or any(name in value and value[name] is not True for name in ('publication_admitted','start_intent'))
     or 'container_id' in value and not re.fullmatch(r'[0-9a-f]{64}',str(value['container_id']))
     or value.get('start_intent') and not value.get('publication_admitted')
     or value.get('phase') in ('published','started','upgraded') and not value.get('publication_admitted')
     or value.get('phase') in ('started','upgraded') and not value.get('container_id')):
  raise RuntimeError('Invalid remote upgrade authority; preserve its record')
 intent=value.get('ca_intent')
 if intent is not None and (not isinstance(intent,dict) or set(intent) not in (
     {'sha256','before'},{'sha256','before','after'}) or not re.fullmatch(r'[0-9a-f]{64}',str(intent.get('sha256')))
     or any(not isinstance(intent.get(name),dict) or set(intent[name])!={'sha256','device','inode','mode','uid','gid'}
            for name in ('before','after') if name in intent)):
  raise RuntimeError('Invalid remote public certificate intent')
 return value
def upgrade_row(record):
 return {'Id':record['Id'],'Image':record['Image'],'Config':{'Labels':record['Config']['Labels']},
         'State':{name:record['State'].get(name) for name in
                  ('Running','StartedAt','Restarting','Dead','OOMKilled','ExitCode')},
         'HostConfig':{'RestartPolicy':record['HostConfig']['RestartPolicy']}}
def upgrade_lock():
 global capture_lock, upgrade_guard_lock
 if 'capture_id' in r: raise RuntimeError('Conflicting remote operation families')
 locks=[]
 for name in ('.backup-capture.lock','.application-upgrade.lock'):
  fd=os.open(root/name,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600); locks.append(fd)
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:
   raise RuntimeError('Unsafe remote upgrade lock')
  try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError: raise RuntimeError('An earlier remote capture or upgrade command is still active')
 capture_lock,upgrade_guard_lock=locks
def upgrade(action):
 upgrade_lock(); owned()
 path=root/'application-upgrade.json'
 saved=upgrade_record(json.loads(upgrade_file(path))) if path.exists() or path.is_symlink() else None
 if action=='upgrade-read':
  if saved is not None and saved.get('phase')!='upgraded':
   raise RuntimeError('Recover the existing remote Console upgrade')
  spec=upgrade_file(root/'compose.json')
  if hashlib.sha256(spec).hexdigest()!=r['digest']: raise RuntimeError('Remote Compose changed')
  record=console_record()
  return {'container':upgrade_row(record),'credentials':upgrade_credentials(),
          'public_ca':base64.b64encode(upgrade_file(root/'ca.pem')).decode(),
          'previous':hashlib.sha256(upgrade_file(path)).hexdigest() if saved is not None else None}
 contract=r['upgrade']; operation=contract['operation_id']
 if (not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',operation)
     or contract['instance_id']!=identity or contract['project']!=project):
  raise RuntimeError('Remote upgrade identity changed')
 signature=hashlib.sha256(upgrade_canonical(contract)).hexdigest()
 if saved is not None and saved.get('operation_id')==operation:
  if saved.get('contract_sha256')!=signature: raise RuntimeError('Remote upgrade plan changed')
 elif saved is not None:
  if saved.get('phase')!='upgraded' or hashlib.sha256(upgrade_file(path)).hexdigest()!=contract['previous']:
   raise RuntimeError('Another remote Console upgrade owns this deployment')
  saved=None
 elif contract['previous'] is not None:
  raise RuntimeError('Previous remote upgrade history is missing')
 credentials=upgrade_credentials()
 if any(credentials.get(name)!=value for name,value in contract['credentials'].items() if name!='ca.pem') or set(credentials)!=set(contract['credentials']):
  raise RuntimeError('Remote Console credentials changed')
 certificate=credentials['ca.pem']; ca_intent=saved.get('ca_intent') if saved is not None else None
 if ca_intent is None: accepted=[contract['credentials']['ca.pem']]
 elif 'after' in ca_intent: accepted=[ca_intent['after']]
 else:
  accepted=[ca_intent['before']]
  if (certificate['sha256']==ca_intent['sha256'] and certificate['uid']==0
      and certificate['gid']==10001 and certificate['mode']==0o644): accepted+=[certificate]
 if certificate not in accepted: raise RuntimeError('Remote public certificate changed outside its intent')
 old=base64.b64decode(contract['before'],validate=True)
 startup=base64.b64decode(contract['startup'],validate=True)
 final=base64.b64decode(contract['final'],validate=True)
 actual=upgrade_file(root/'compose.json')
 if actual not in (old,startup,final): raise RuntimeError('Unapproved remote Compose bytes')
 spec=json.loads(startup)['services']['console']
 if (set(json.loads(startup)['services'])!={'console'} or spec['image']!=contract['image']
     or spec.get('restart')!='no' or spec.get('build') is not None or spec.get('pull_policy')!='never'
     or spec.get('labels',{}).get('com.cisco.iris.application-upgrade')!=operation):
  raise RuntimeError('Invalid remote candidate specification')
 r['image']=contract['old_image']
 def record():
  found=run(['docker','container','ls','--all','--no-trunc','--filter',
             'name=^/'+re.escape(spec['container_name'])+'$','--format','{{.ID}}']).decode().strip()
  if not found:
   if saved is None or not saved.get('start_intent') or saved.get('container_id'):
    raise RuntimeError('An acquired Console disappeared')
   return None
  row,=json.loads(run(['docker','container','inspect',found]))
  labels=row['Config'].get('Labels',{})
  if (labels.get('com.cisco.iris.installer')!=identity
      or labels.get('com.docker.compose.project')!=project
      or labels.get('com.docker.compose.service')!='console'):
   raise RuntimeError('Remote Console ownership changed')
  original=row['Id']==contract['container_id'] and row['Image']==contract['old_image']
  acquired=(saved is not None and saved.get('start_intent') and row['Image']==contract['image']
            and labels.get('com.cisco.iris.application-upgrade')==operation
            and (not saved.get('container_id') or saved['container_id']==row['Id']))
  if not original and not acquired: raise RuntimeError('Remote Console identity changed')
  # Reuse the complete mount/foreign-writer census, for either admitted image.
  r['image']=row['Image']; checked=console_record()
  if checked['Id']!=row['Id']: raise RuntimeError('Remote Console changed during observation')
  return row
 def save(): write('application-upgrade.json',upgrade_canonical(saved),0o600)
 row=record()
 if saved is None:
  if action!='upgrade-fence' or actual!=old or row is None or row['Id']!=contract['container_id']:
   raise RuntimeError('The original remote upgrade fence is not recorded')
  saved={'operation_id':operation,'contract_sha256':signature,'phase':'fencing'}; save()
 if action=='upgrade-credentials': return credentials
 if action=='upgrade-observe':
  if row is None: return None
  return upgrade_row(row)
 if action=='upgrade-fence':
  if row is not None:
   run(['docker','update','--restart=no',row['Id']])
   run(['docker','stop','--time','120',row['Id']])
   row=record()
   if row['State']['Running'] or row['HostConfig']['RestartPolicy']['Name']!='no':
    raise RuntimeError('Remote Console did not fence')
  saved['phase']='fenced'; save()
 elif action=='upgrade-publish':
  if row is not None and row['State']['Running']: raise RuntimeError('Remote Console is still running')
  saved['publication_admitted']=True; save()
  write('compose.json',startup,0o644)
  saved['phase']='published'; save()
 elif action=='upgrade-sync-ca':
  if not saved.get('publication_admitted'): raise RuntimeError('Publish the approved candidate before refreshing public trust')
  if row is not None and row['State']['Running']: raise RuntimeError('Stop the Console before refreshing its public certificate')
  payload=base64.b64decode(r['public_ca'],validate=True)
  old_ca=base64.b64decode(contract['public_ca'],validate=True)
  if (len(payload)>65536 or len(old_ca)>65536
      or hashlib.sha256(old_ca).hexdigest()!=contract['credentials']['ca.pem']['sha256']):
   raise RuntimeError('Invalid public certificate input')
  argv=['openssl','x509','-pubkey','-subject','-issuer','-noout']
  if run(argv,payload)!=run(argv,old_ca): raise RuntimeError('Management public key or issuer changed')
  wanted=hashlib.sha256(payload).hexdigest()
  expected=r['certificate_before']
  if ca_intent is not None and 'after' not in ca_intent and ca_intent['sha256']!=wanted:
   raise RuntimeError('Settle the original public certificate intent before a successor')
  if certificate!=expected and not (ca_intent is not None and ca_intent['sha256']==wanted
                                   and ca_intent['before']==expected and certificate['sha256']==wanted):
   raise RuntimeError('Public certificate preimage changed')
  if certificate['sha256']!=wanted:
   if ca_intent is None or ca_intent['sha256']!=wanted or ca_intent['before']!=expected:
    saved['ca_intent']={'sha256':wanted,'before':expected}; save()
   write('ca.pem',payload,0o644)
  if 'ca_intent' in saved and saved['ca_intent']['sha256']==wanted:
   saved['ca_intent']['after']=upgrade_credentials()['ca.pem']; save()
  return upgrade_credentials()
 elif action=='upgrade-start':
  if actual!=startup or not saved.get('publication_admitted'):
   raise RuntimeError('Remote startup publication is not complete')
  if run(['docker','image','inspect',contract['image'],'--format','{{.Id}}']).decode().strip()!=contract['image']:
   raise RuntimeError('Approved remote Console image changed')
  saved['start_intent']=True; save()
  # A lost reply may have completed creation/start. Acquire that exact new
  # identity under both inherited locks before considering another command.
  # A running approved incarnation is observed, not recreated/restarted.
  existing=row is not None and row['Image']==contract['image']
  if existing:
   saved['container_id']=row['Id']; save()
  if not existing or not row['State']['Running']:
   run(['docker','compose','-p',project,'-f',str(root/'compose.json'),'up','-d',
        '--no-build','--no-deps','--pull','never','--wait','--wait-timeout','180','console'])
   row=record()
  if row is None or row['Image']!=contract['image'] or not row['State']['Running']:
   raise RuntimeError('Approved remote Console did not start')
  r['container_id']=row['Id']; r['started_at']=row['State']['StartedAt']
  proof_runtime(row,spec)
  if row['State'].get('Health',{}).get('Status','healthy')!='healthy':
   raise RuntimeError('Acquired remote Console is not healthy yet; recover the same operation')
  saved['container_id']=row['Id']; saved['phase']='started'; save()
 elif action=='upgrade-finish':
  if (row is None or row['Image']!=contract['image'] or not row['State']['Running']
      or saved.get('container_id')!=row['Id'] or not saved.get('publication_admitted')):
   raise RuntimeError('Remote completion has no verified acquired Console')
  write('compose.json',final,0o644)
  policy=json.loads(final)['services']['console'].get('restart','no')
  run(['docker','update','--restart='+policy,row['Id']])
  after=record()
  if after['HostConfig']['RestartPolicy']['Name']!=policy or not after['State']['Running']:
   raise RuntimeError('Remote restart policy did not finalize')
  saved['phase']='upgraded'; save()
 else: raise RuntimeError('Unsupported remote upgrade action')
 return upgrade_row(row) if row is not None else None
'''


def remote_program(original):
    """Extend only the fixed split transport program, keeping its core checks."""
    plan.require(original.count("action=r['action']") == 1
                 and original.count("if action=='claim': pass") == 1
                 and original.count('pass_fds=(capture_lock,) if capture_lock is not None else ()') == 1,
                 'The fixed split transport program changed')
    return original.replace("action=r['action']", REMOTE_EXTENSION + "\naction=r['action']").replace(
        "if action=='claim': pass",
        "if action.startswith('upgrade-'): sys.stdout.write(json.dumps(upgrade(action)))\nelif action=='claim': pass").replace(
        'pass_fds=(capture_lock,) if capture_lock is not None else ()',
        "pass_fds=tuple(fd for fd in (capture_lock,globals().get('upgrade_guard_lock')) if fd is not None)")


def snapshot(install):
    completed = install.journal.document['completed']
    raw = regular_bytes(install.console_file)
    plan.require(hashlib.sha256(raw).hexdigest() == completed['console-prepared'],
                 'Original Console Compose changed')
    plan.require(hashlib.sha256(regular_bytes(install.console_build_file)).hexdigest() == completed['split-prepared'],
                 'Original Console build definition changed')
    answer = json.loads(install.remote('upgrade-read', digest=completed['console-prepared'],
                                     image=completed['console-image']))
    return {'compose_before': raw.decode('utf-8'),
            'build_before': regular_bytes(install.console_build_file).decode('utf-8'), **answer}


def contract(install, operation):
    before, built = operation.record['split_before'], operation.record['candidate']
    encode = lambda value: base64.b64encode(value).decode('ascii')
    return {'operation_id': operation.id, 'instance_id': operation.instance,
        'project': install.config['instance'], 'container_id': before['container']['Id'],
        'old_image': before['container']['Image'], 'image': built['images']['console'],
        'credentials': before['credentials'], 'previous': before['previous'],
        'public_ca': before['public_ca'],
        'before': encode(before['compose_before'].encode()),
        'startup': encode(plan.canonical(plan.startup_compose(built['console_compose'], services=('console',)))),
        'final': encode(plan.canonical(built['console_compose']))}


def remote(install, operation, action, **values):
    return json.loads(install.remote('upgrade-' + action, upgrade=contract(install, operation), timeout=300, **values))


def sync_ca(install, operation, producer):
    """Forward-only public CA refresh; never rotate tokens or private keys.

    Settle any exact previous response-loss intent first. A further server
    restart may generate a new certificate only under the same original key,
    subject and issuer, with its own durable sequential publication record.
    """
    before = operation.record['split_before']
    rows = operation.record.setdefault('split_public_certificates', [])
    plan.require(isinstance(rows, list) and len(rows) <= 16, 'Too many retained management certificate transitions')
    for row in rows:
        if 'after' not in row:
            result = remote(install, operation, 'sync-ca', public_ca=row['public_ca'], certificate_before=row['before'])
            row['after'] = result['ca.pem']; operation.save()
    answer = json.loads(install.python(
        "import base64,hashlib,json,pathlib; p=pathlib.Path('/run/iris-tier'); "
        "v={n:hashlib.sha256((p/n).read_bytes() if (p/n).exists() else b'').hexdigest() "
        "for n in ('current.json','previous.json')}; "
        "v['ca']=base64.b64encode(pathlib.Path('/run/iris-management-ca/ca.pem').read_bytes()).decode(); print(json.dumps(v))"))
    plan.require(isinstance(answer, dict) and set(answer) == {'current.json', 'previous.json', 'ca'},
                 'Invalid authenticated management public export')
    for name in ('current.json', 'previous.json'):
        plan.require(answer[name] == before['credentials'].get(name, {'sha256': hashlib.sha256(b'').hexdigest()})['sha256'],
                     'Management bearer credentials changed during upgrade')
    public = base64.b64decode(answer['ca'], validate=True)
    old = base64.b64decode(before['public_ca'], validate=True)
    plan.require(0 < len(public) <= 65536 and 0 < len(old) <= 65536, 'Oversized management public certificate')
    arguments = ['openssl', 'x509', '-pubkey', '-subject', '-issuer', '-noout']
    plan.require(install.command(arguments, input=public, capture=True, timeout=30)
                 == install.command(arguments, input=old, capture=True, timeout=30),
                 'Management public key, subject or issuer changed during upgrade')
    current = remote(install, operation, 'credentials')['ca.pem']
    wanted = hashlib.sha256(public).hexdigest()
    if current['sha256'] == wanted:
        return current
    plan.require(len(rows) < 16, 'Management certificate transition history is full')
    row = {'public_ca': answer['ca'], 'before': current, 'producer': producer}
    rows.append(row); operation.save()
    result = remote(install, operation, 'sync-ca', public_ca=row['public_ca'], certificate_before=current)
    row['after'] = result['ca.pem']; operation.save()
    return row['after']


def publish_local(install, built, before, *, startup):
    for path, old, final, services in (
            (install.console_file, before['compose_before'], built['console_compose'], ('console',)),
            (install.console_build_file, before['build_before'], built['console_build'], ('console',))):
        replacement = plan.startup_compose(final, services=services) if startup and path == install.console_file else final
        allowed = (old.encode(), plan.canonical(final),
                   plan.canonical(plan.startup_compose(final, services=services)))
        plan.require(regular_bytes(path) in allowed, 'Local split Compose publication found unapproved bytes')
        atomic_write(path, plan.canonical(replacement))


def candidate(install, old, new, images):
    """Preserve every live split override; release layout must remain identical."""
    plan.require(plan.canonical(plan.runtime_contract(old)) == plan.canonical(plan.runtime_contract(new)),
                 'This release changes the split runtime layout; an explicit migration is required')
    before = snapshot(install)
    local = json.loads(regular_bytes(install.compose_file))
    console = json.loads(before['compose_before'])
    # The recorded live definitions already carry the explicit split mounts,
    # management endpoint, transport and credential-rotation overrides.
    patched = {}
    templates = [split_templates(install, value) for value in (old, new)]
    for name, current in (('iris', local), ('console', console)):
        patched[name] = plan.candidate_compose(current, templates[0][name], templates[1][name],
                                             {name: images[name]}, services=(name,))
        labels = patched[name]['services'][name].setdefault('labels', {})
        plan.require(isinstance(labels, dict), 'Split candidate labels must be explicit mappings')
        labels['com.cisco.iris.application-upgrade'] = install.application_upgrade_id
    build = json.loads(before['build_before'])
    plan.runtime_contract(build, services=('console',))
    build['services']['console'].update(image=images['console'], pull_policy='never')
    build['services']['console'].pop('build', None)
    install._transfer_image(images['console'])
    plan.require(install.remote('inspect', image=images['console']).decode().strip() == images['console'],
                 'Approved Console image was not preloaded on the recorded host')
    plan.require(snapshot(install) == before, 'Remote Console custody changed during candidate preparation')
    return patched['iris'], patched['console'], build, before


def split_templates(install, combined):
    """Exact prepare/build split projection, before preserving live overrides.

    Managed split installation uses the combined Compose template, not the
    separately documented checkout files. This projection mirrors those
    adapter transformations for both source generations under identical inputs.
    """
    plan.runtime_contract(combined)
    server = copy.deepcopy(combined)
    console = server['services'].pop('console')
    server['services']['iris'].setdefault('environment', {})['IRIS_INSTALLER_TARGET'] = 'docker-split'
    server['services']['iris'].setdefault('ports', []).append({
        'target': 9443, 'published': '9443', 'host_ip': install.config['management_bind'], 'protocol': 'tcp'})
    console.pop('depends_on', None)
    console.pop('build', None)
    console.setdefault('environment', {}).update(
        IRIS_MANAGEMENT_API_URL='https://' + install.config['management_bind'] + ':9443',
        IRIS_RUNTIME_HOST=install.config['console_ssh_host'],
        IRIS_GUI_DEFAULT_CERT='/run/iris-console-custody/tls.crt',
        IRIS_GUI_DEFAULT_KEY='/run/iris-console-custody/tls.key',
        IRIS_MANAGEMENT_API_TOKEN_FILE='/run/iris-console-custody/current.json',
        IRIS_MANAGEMENT_API_PREVIOUS_TOKEN_FILE='/run/iris-console-custody/previous.json',
        IRIS_MANAGEMENT_API_CA='/run/iris-console-custody/ca.pem')
    console['volumes'] = [{'type': 'bind', 'source': install.config['console_state_dir'],
                          'target': '/run/iris-console-custody', 'read_only': True,
                          'bind': {'create_host_path': False}}]
    remote_console = {'name': install.config['instance'], 'services': {'console': console},
                      'networks': {'default': {'labels': {'com.cisco.iris.installer': install.journal.document['id']}}}}
    return {'iris': server, 'console': remote_console}
