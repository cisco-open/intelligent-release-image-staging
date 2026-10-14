# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Actual fixed remote program/locks, modelled Docker; no SSH or live deployment."""

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import socket
import ssl
import sys
import tempfile
import threading
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import upgrade_plan as plan, upgrade_split as split
from iris_installer import application_upgrade as upgrade, backup, upgrade_runtime as runtime
from iris_installer.split_deploy import REMOTE_PROGRAM
from iris_installer.state import InstallError, atomic_write
from test_installer_upgrade_transaction import transaction, assert_preserved

INSTANCE = '1e2ac67b-07c1-4e94-a66b-08b19f8e2d75'
OPERATION = '7f761c39-450f-4101-836e-6515449d7b28'
OLD = 'sha256:' + '3' * 64
NEW = 'sha256:' + '2' * 64
OLD_ID, NEW_ID = 'a' * 64, 'b' * 64


DOCKER = r'''#!/usr/bin/python3
import json,os,sys
from pathlib import Path
path=Path(os.environ['MODEL']);model=json.loads(path.read_bytes());args=sys.argv[1:]
model.setdefault('commands',[]).append(args)
locks=[]
for fd in Path('/proc/self/fd').iterdir():
 try:
  if os.readlink(fd).endswith('/.application-upgrade.lock'):locks.append(int(fd.name))
 except OSError:pass
model.setdefault('inherited_locks',[]).append(locks)
def save():path.write_text(json.dumps(model))
def out(value):save();print(value);raise SystemExit(0)
row=model.get('row')
if args[:2] in (['container','ls'],['volume','ls'],['network','ls']):
 out(row['Id'] if args[0]=='container' and row is not None else '')
if args[:2]==['image','inspect']:out(args[2])
if args[:2] in (['container','inspect'],['inspect']):
 selected=args[2] if args[0]=='container' else args[1]
 if row is None or selected not in (row['Id'],'owned-console'):save();raise SystemExit(5)
 out(json.dumps([row]))
if args[0]=='update':row['HostConfig']['RestartPolicy']['Name']=args[1].split('=',1)[1];out('')
if args[0]=='stop':row['State'].update(Running=False,ExitCode=0);out('')
if args[0]=='compose' and 'up' in args:
 spec=json.loads(Path(args[args.index('-f')+1]).read_bytes())['services']['console']
 failure=model.get('failure') if not model.get('failed') else None
 if failure=='after-remove':model.update(row=None,failed=True);save();raise SystemExit(8)
 if row is None or row['Image']!=spec['image']:
  row=dict(Id='b'*64,Image=spec['image'],Config={'Labels':dict(spec['labels'],**{
   'com.docker.compose.project':'owned','com.docker.compose.service':'console'}),
   'Env':[str(k)+'='+str(v) for k,v in spec['environment'].items()]},
   State={'Running':True,'ExitCode':0,'StartedAt':'new-birth'},
   HostConfig={'RestartPolicy':{'Name':spec['restart']}},Mounts=model['mounts'])
  model['row']=row
 else:row['State']['Running']=True
 if failure=='after-create':model['failed']=True;save();raise SystemExit(8)
 out('')
save();raise RuntimeError(args)
'''


@pytest.fixture
def remote(request):
    if os.geteuid() != 0:
        pytest.skip('Actual root-owned remote program requires root')
    temporary = tempfile.TemporaryDirectory(prefix='iris-split-upgrade-test-', dir='/var/lib')
    request.addfinalizer(temporary.cleanup)
    tmp_path = Path(temporary.name)
    root = tmp_path / 'console'; root.mkdir(mode=0o750)
    atomic_write(root / 'owner.json', plan.canonical({'instance_id': INSTANCE, 'project': 'owned'}))
    for name in ('current.json', 'previous.json', 'ca.pem', 'tls.crt', 'tls.key'):
        atomic_write(root / name, ('retained:' + name).encode(),
                     0o640 if name in ('current.json', 'previous.json', 'tls.key') else 0o644)
    ca_key, old_ca, new_ca = (tmp_path / name for name in ('management-key.pem', 'old-ca.pem', 'new-ca.pem'))
    subprocess.run(['openssl', 'genrsa', '-out', str(ca_key), '2048'], check=True, capture_output=True)
    for path in (old_ca, new_ca):
        subprocess.run(['openssl', 'req', '-x509', '-new', '-key', str(ca_key), '-days', '1',
            '-subj', '/CN=iris', '-addext', 'subjectAltName=DNS:localhost', '-out', str(path)],
            check=True, capture_output=True)
    atomic_write(root / 'ca.pem', old_ca.read_bytes(), 0o644)
    spec = {'name': 'owned', 'services': {'console': {'image': OLD,
        'container_name': 'owned-console', 'restart': 'unless-stopped',
        'labels': {'com.cisco.iris.installer': INSTANCE},
        'environment': {'IRIS_MANAGEMENT_API_TOKEN_FILE': '/existing/current.json'},
        'volumes': [{'type': 'bind', 'source': str(root), 'target': '/run/iris-console-custody', 'read_only': True}]}}}
    before = plan.canonical(spec); atomic_write(root / 'compose.json', before, 0o644)
    final = plan.candidate_compose(spec, spec, spec, {'console': NEW}, services=('console',))
    final['services']['console']['labels']['com.cisco.iris.application-upgrade'] = OPERATION
    startup = plan.startup_compose(final, services=('console',))
    mounts = [{'Type': 'bind', 'Source': str(root), 'Destination': '/run/iris-console-custody', 'RW': False}]
    row = dict(Id=OLD_ID, Image=OLD, Config={'Labels': {'com.cisco.iris.installer': INSTANCE,
        'com.docker.compose.project': 'owned', 'com.docker.compose.service': 'console'}},
        State={'Running': True, 'ExitCode': 0, 'StartedAt': 'old-birth'},
        HostConfig={'RestartPolicy': {'Name': 'unless-stopped'}}, Mounts=mounts)
    model = tmp_path / 'model.json'; atomic_write(model, plan.canonical({'row': row, 'mounts': mounts}))
    commands = tmp_path / 'commands'; commands.mkdir()
    atomic_write(commands / 'docker', DOCKER.encode(), 0o755)
    env = dict(os.environ, PATH=str(commands) + ':/usr/bin:/bin', MODEL=str(model))
    program = split.remote_program(REMOTE_PROGRAM)
    compile(program, 'fixed-remote-program', 'exec')
    programs = {'current': program, 'original': program}

    def invoke(action, *, checked=True, **values):
        payload = dict(action='upgrade-' + action, root=str(root), identity=INSTANCE, project='owned', **values)
        result = subprocess.run([sys.executable, '-I', '-B', '-c', programs['current']],
                                input=plan.canonical(payload), env=env, capture_output=True, timeout=5)
        if checked:
            assert result.returncode == 0, result.stderr.decode()
            return json.loads(result.stdout)
        return result

    snapshot = invoke('read', image=OLD, digest=hashlib.sha256(before).hexdigest())
    encode = lambda raw: base64.b64encode(raw).decode()
    contract = dict(operation_id=OPERATION, instance_id=INSTANCE, project='owned',
        container_id=OLD_ID, old_image=OLD, image=NEW, credentials=snapshot['credentials'],
        previous=snapshot['previous'], public_ca=snapshot['public_ca'], before=encode(before), startup=encode(plan.canonical(startup)),
        final=encode(plan.canonical(final)))
    def call(action, *, checked=True):
        return invoke(action, checked=checked, upgrade=contract)
    return SimpleNamespace(root=root, model=model, contract=contract, invoke=invoke,
                           call=call, before=before, final=final, startup=startup,
                           new_ca=new_ca.read_bytes(), ca_key=ca_key, programs=programs)


def test_remote_forward_upgrade_retains_credentials_and_records_exact_new_id(remote):
    old = {name: (remote.root / name).read_bytes() for name in remote.contract['credentials']}
    remote.call('fence'); remote.call('publish')
    row = remote.call('start'); assert row['Id'] == NEW_ID and row['Image'] == NEW
    assert remote.call('credentials') == remote.contract['credentials']
    remote.call('finish')
    assert json.loads((remote.root / 'application-upgrade.json').read_bytes())['phase'] == 'upgraded'
    assert (remote.root / 'compose.json').read_bytes() == plan.canonical(remote.final)
    assert all((remote.root / name).read_bytes() == data for name, data in old.items())
    assert all(fds for fds in json.loads(remote.model.read_bytes())['inherited_locks'])


@pytest.mark.parametrize('failure', ['after-remove', 'after-create'])
def test_unknown_remote_create_reconciles_same_operation_without_adopting_replacement(remote, failure):
    remote.call('fence'); remote.call('publish')
    model = json.loads(remote.model.read_bytes()); model['failure'] = failure
    atomic_write(remote.model, plan.canonical(model))
    result = remote.call('start', checked=False)
    assert result.returncode != 0
    assert json.loads((remote.root / 'application-upgrade.json').read_bytes())['start_intent'] is True
    row = remote.call('start'); assert row['Id'] == NEW_ID
    commands = json.loads(remote.model.read_bytes())['commands']
    assert sum(args[0] == 'compose' and 'up' in args for args in commands) == (2 if failure == 'after-remove' else 1)
    # A lost successful reply can be observed/reentered, but cannot acquire a
    # later same-image replacement merely through its installer label.
    assert remote.call('observe')['Id'] == NEW_ID
    model = json.loads(remote.model.read_bytes()); model['row']['Id'] = 'c' * 64
    atomic_write(remote.model, plan.canonical(model))
    result = remote.call('start', checked=False)
    assert result.returncode != 0 and b'identity changed' in result.stderr


@pytest.mark.parametrize('damage', ['credentials', 'compose', 'container', 'plan', 'missing-acquired'])
def test_remote_change_refuses_before_any_additional_command(remote, damage):
    remote.call('fence'); remote.call('publish'); remote.call('start')
    if damage == 'credentials': atomic_write(remote.root / 'tls.key', b'changed', 0o640)
    elif damage == 'compose': atomic_write(remote.root / 'compose.json', b'{}', 0o644)
    elif damage == 'plan': remote.contract['image'] = 'sha256:' + '9' * 64
    else:
        model = json.loads(remote.model.read_bytes())
        if damage == 'container': model['row']['Id'] = 'c' * 64
        else: model['row'] = None
        atomic_write(remote.model, plan.canonical(model))
    result = remote.call('fence', checked=False)
    assert result.returncode != 0
    assert json.loads(remote.model.read_bytes())['row'] is None or json.loads(remote.model.read_bytes())['row']['State']['Running']


@pytest.mark.parametrize('lock_name', ['.application-upgrade.lock', '.backup-capture.lock'])
def test_live_remote_writer_lock_refuses_then_same_operation_continues(remote, lock_name):
    remote.call('fence')
    child = subprocess.Popen([sys.executable, '-I', '-B', '-c',
        "import fcntl,sys; f=open(sys.argv[1],'r+'); fcntl.flock(f,fcntl.LOCK_EX); print('held',flush=True); sys.stdin.read()",
        str(remote.root / lock_name)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        assert child.stdout.readline() == b'held\n'
        result = remote.call('observe', checked=False)
        assert result.returncode != 0 and b'still active' in result.stderr
    finally:
        child.communicate(timeout=5)
    assert child.returncode == 0
    remote.call('publish'); assert remote.call('start')['Id'] == NEW_ID


def test_remote_read_never_adopts_unfinished_previous_operation(remote):
    remote.call('fence')
    result = remote.invoke('read', checked=False, image=OLD,
                           digest=hashlib.sha256(remote.before).hexdigest())
    assert result.returncode != 0 and b'Recover the existing' in result.stderr


def test_split_checkpoint_publication_keeps_transport_and_identity():
    original = {'schema': 1, 'id': INSTANCE, 'config': {'target': 'docker-split'},
        'state': 'PRODUCTION_REVIEW_REQUIRED', 'source_manifest': {'old.py': 'a' * 64},
        'root_digests': {'a.pub': 'a' * 64, 'b.pub': 'b' * 64},
        'completed': {'prepared': 'c' * 64, 'images': {OLD: OLD}, 'signing': True, 'guestshell': {'state': 'ok'},
            'packages': {name: 'd' * 64 for name in plan.NATIVE_FILES},
            'split-prepared': 'e' * 64, 'console-prepared': 'f' * 64,
            'console-image': OLD, 'split-transport': {'console_ssh_key': '1' * 64, 'console_known_hosts': '2' * 64}}}
    server = {'services': {'iris': {'image': 'sha256:' + '1' * 64}}}
    console = {'services': {'console': {'image': NEW}}}
    result = plan.next_journal(original, operation_id=OPERATION, source={'new.py': '9' * 64},
        compose=server, console_compose=console, console_build=console,
        packages=original['completed']['packages'], guestshell={'state': 'ok'})
    assert result['id'] == original['id'] and result['root_digests'] == original['root_digests']
    assert result['completed']['split-transport'] == original['completed']['split-transport']
    assert result['completed']['console-image'] == NEW
    assert result['completed']['console-prepared'] == hashlib.sha256(plan.canonical(console)).hexdigest()
    with pytest.raises(InstallError):
        plan.next_journal(original, operation_id=OPERATION, source={'new.py': '9' * 64},
            compose=server, packages=original['completed']['packages'], guestshell={'state': 'ok'})


@pytest.fixture
def split_transaction(transaction, remote, monkeypatch):
    """Use the real transaction/publication and exact remote program together."""
    tx = transaction
    original = copy.deepcopy(tx.original)
    original['config']['target'] = 'docker-split'
    console_build = {'services': {'console': {'image': OLD}}}
    before = {'compose_before': remote.before.decode(), 'build_before': plan.canonical(console_build).decode(),
        'container': remote.invoke('read', image=OLD, digest=hashlib.sha256(remote.before).hexdigest())['container'],
        'credentials': remote.contract['credentials'], 'previous': None, 'public_ca': remote.contract['public_ca']}
    original['completed'].update({'split-prepared': hashlib.sha256(plan.canonical(console_build)).hexdigest(),
        'console-prepared': hashlib.sha256(remote.before).hexdigest(), 'console-image': OLD,
        'split-transport': {'console_ssh_key': '1' * 64, 'console_known_hosts': '2' * 64}})
    original['completed']['images']['old-console'] = OLD
    original_compose = json.loads((tx.base / 'compose.json').read_bytes())
    original_compose['services'].pop('console')
    raw_compose = plan.canonical(original_compose)
    original['completed']['prepared'] = hashlib.sha256(raw_compose).hexdigest()
    atomic_write(tx.base / 'compose.json', raw_compose)
    atomic_write(tx.base / 'console-compose.json', remote.before)
    atomic_write(tx.base / 'console-build.json', plan.canonical(console_build))
    atomic_write(tx.base / 'installation.json', plan.canonical(original))
    review = json.loads((tx.operation.directory / 'plan.json').read_bytes())
    review.update(original=original, compose_before=raw_compose.decode(), split_before=before)
    built = review['candidate']
    built['compose']['services'].pop('console')
    built.update(console_compose=remote.final, console_build={'services': {'console': {'image': NEW}}},
                 split_before=before)
    rows = [dict(id=OLD_ID, service='console', remote=True, running=True),
            dict(id='old-iris', service='iris', running=True)]
    review['resources']['containers'] = rows
    # These are construction of isolated initial test inputs, not replacement
    # of an already reviewed real operation or a supported host mutation.
    tx.operation.record.update(original=original, candidate=built, split_before=before)
    raw_plan = plan.canonical(review)
    atomic_write(tx.operation.directory / 'plan.json', raw_plan)
    tx.operation.record['plan_sha256'] = hashlib.sha256(raw_plan).hexdigest(); tx.operation.save()
    tx.args.plan_sha256 = tx.operation.record['plan_sha256']; tx.original = original
    cls = upgrade.deploy.DockerInstall
    def construct(journal):
        install = cls(journal)
        install.console_file, install.console_build_file = tx.base / 'console-compose.json', tx.base / 'console-build.json'
        install.remote = lambda action, **values: plan.canonical(remote.invoke(action.removeprefix('upgrade-'), **{
            key: value for key, value in values.items() if key != 'timeout'}))
        original_command = install.command
        def command(argv, **kwargs):
            if argv[0] == 'openssl':
                return subprocess.run(argv, input=kwargs['input'], capture_output=True, check=True).stdout
            output = original_command(argv, **kwargs)
            if argv[:2] == ['docker', 'inspect']:
                records = json.loads(output)
                for item in records: item['State']['StartedAt'] = 'held-local-server-birth'
                return plan.canonical(records)
            return output
        install.command = command
        install.python = lambda code: plan.canonical(dict({name: remote.contract['credentials'][name]['sha256']
                for name in ('current.json', 'previous.json')}, ca=base64.b64encode(remote.new_ca).decode()))
        return install
    monkeypatch.setattr(upgrade, '_construction', construct)
    def capture(install, **kwargs):
        row = json.loads(remote.model.read_bytes())['row']
        local = tx.control['containers']['iris']
        return {'volume-iris-state': tx.base / 'volume-iris-state',
                'volume-iris-config': tx.base / 'volume-iris-config'}, review['resources']['volumes'], [
            {'id': row['Id'], 'service': 'console', 'remote': True, 'running': row['State']['Running']},
            {key: local[key] for key in ('id', 'service', 'running')}]
    monkeypatch.setattr(backup, 'capture_plan', capture)
    tx.remote = remote
    return tx


def test_split_full_transaction_publishes_both_generations_and_keeps_authority(split_transaction):
    tx = split_transaction
    assert upgrade.apply(tx.args) == 0
    result = json.loads((tx.base / 'installation.json').read_bytes())
    assert result['completed']['console-image'] == NEW
    assert result['completed']['console-prepared'] == hashlib.sha256(plan.canonical(tx.remote.final)).hexdigest()
    assert tx.remote.call('observe')['Id'] == NEW_ID
    assert_preserved(tx)


@pytest.mark.parametrize('boundary', ['start-iris', 'consumer', 'refresh-worker', 'enable-iris'])
def test_split_same_operation_recovers_after_local_or_remote_publication(split_transaction, boundary):
    tx = split_transaction; tx.control['failure'] = boundary
    with pytest.raises(InstallError, match='injected'):
        upgrade.apply(tx.args)
    assert tx.remote.call('observe')['State']['Running'] is False
    assert upgrade.apply(tx.args, recovery=True) == 0
    assert tx.remote.call('observe')['Image'] == NEW
    assert_preserved(tx)


def test_split_actual_unknown_start_is_recovered_without_new_backup(split_transaction):
    tx = split_transaction
    model = json.loads(tx.remote.model.read_bytes()); model['failure'] = 'after-create'
    atomic_write(tx.remote.model, plan.canonical(model))
    with pytest.raises(AssertionError, match='Remote operation failed'):
        upgrade.apply(tx.args)
    assert json.loads(tx.operation.path.read_bytes())['phase'] == 'recovery-required'
    assert tx.remote.call('observe')['State']['Running'] is False
    assert upgrade.apply(tx.args, recovery=True) == 0
    assert tx.control['events'].count('backup') == 1
    assert tx.remote.call('observe')['Id'] == NEW_ID
    assert_preserved(tx)


def test_reconstructed_management_certificate_rejects_unchanged_remote_ca(tmp_path):
    """Actual OpenSSL/Python TLS for the entrypoint's same-key bootstrap path."""
    key, old, new = (tmp_path / name for name in ('key.pem', 'old.pem', 'new.pem'))
    subprocess.run(['openssl', 'genrsa', '-out', str(key), '2048'], check=True, capture_output=True)
    for path in (old, new):
        subprocess.run(['openssl', 'req', '-x509', '-new', '-key', str(key), '-days', '1',
            '-subj', '/CN=iris', '-addext', 'subjectAltName=DNS:localhost', '-out', str(path)],
            check=True, capture_output=True)
    assert old.read_bytes() != new.read_bytes()
    listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(5)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(new, key)
    errors = []
    def serve():
        try:
            with listener.accept()[0] as incoming:
                with context.wrap_socket(incoming, server_side=True) as connection:
                    connection.sendall(b'new generation')
        except BaseException as error: errors.append(error)
    thread = threading.Thread(target=serve); thread.start()
    try:
        trust = ssl.create_default_context(cafile=str(old))
        with socket.create_connection(listener.getsockname(), timeout=5) as connection:
            with pytest.raises(ssl.SSLCertVerificationError, match='self-signed certificate'):
                trust.wrap_socket(connection, server_hostname='localhost')
    finally:
        listener.close(); thread.join(timeout=6)
    assert not thread.is_alive() and len(errors) == 1 and isinstance(errors[0], ssl.SSLError)


def test_real_management_tls_accepts_journaled_same_key_refresh(remote):
    remote.call('fence'); remote.call('publish')
    original_private = {name: (remote.root / name).read_bytes() for name in remote.contract['credentials'] if name != 'ca.pem'}
    answer = remote.invoke('sync-ca', upgrade=remote.contract,
        public_ca=base64.b64encode(remote.new_ca).decode(), certificate_before=remote.contract['credentials']['ca.pem'])
    assert answer['ca.pem']['sha256'] == hashlib.sha256(remote.new_ca).hexdigest()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    certificate = remote.ca_key.with_name('served-new.pem'); atomic_write(certificate, remote.new_ca, 0o644)
    context.load_cert_chain(certificate, remote.ca_key)
    listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(5)
    errors = []
    def serve():
        try:
            with listener.accept()[0] as incoming:
                with context.wrap_socket(incoming, server_side=True) as secure: secure.sendall(b'authenticated')
        except BaseException as error: errors.append(error)
    thread = threading.Thread(target=serve); thread.start()
    try:
        trust = ssl.create_default_context(cafile=str(remote.root / 'ca.pem'))
        with socket.create_connection(listener.getsockname(), timeout=5) as incoming:
            with trust.wrap_socket(incoming, server_hostname='localhost') as secure:
                assert secure.recv(64) == b'authenticated'
    finally:
        listener.close(); thread.join(timeout=6)
    assert not thread.is_alive() and not errors
    assert all((remote.root / name).read_bytes() == raw for name, raw in original_private.items())


def test_unknown_ca_write_reconciles_exact_intent_without_writing_again(remote):
    remote.call('fence'); remote.call('publish')
    remote.programs['current'] = remote.programs['original'].replace(
        "write('ca.pem',payload,0o644)", "write('ca.pem',payload,0o644); raise RuntimeError('lost public certificate reply')")
    request = dict(upgrade=remote.contract, public_ca=base64.b64encode(remote.new_ca).decode(),
                   certificate_before=remote.contract['credentials']['ca.pem'])
    failed = remote.invoke('sync-ca', checked=False, **request)
    assert failed.returncode != 0 and b'lost public certificate reply' in failed.stderr
    saved = json.loads((remote.root / 'application-upgrade.json').read_bytes())
    assert 'after' not in saved['ca_intent']
    inode = (remote.root / 'ca.pem').stat().st_ino
    remote.programs['current'] = remote.programs['original']
    observed = remote.invoke('sync-ca', **request)
    assert (remote.root / 'ca.pem').stat().st_ino == inode
    assert observed['ca.pem']['sha256'] == saved['ca_intent']['sha256']
    assert json.loads((remote.root / 'application-upgrade.json').read_bytes())['ca_intent']['after'] == observed['ca.pem']


@pytest.mark.parametrize('generation', ['original', 'previous-after'])
def test_acquired_ca_identity_never_accepts_rollback_to_an_earlier_certificate(remote, generation):
    remote.call('fence'); remote.call('publish')
    remote.programs['current'] = remote.programs['original'].replace(
        "write('ca.pem',payload,0o644)",
        "os.link(root/'ca.pem',root/('retained-'+hashlib.sha256(upgrade_file(root/'ca.pem')).hexdigest()+'.pem')); write('ca.pem',payload,0o644)")
    initial = remote.contract['credentials']['ca.pem']
    after = remote.invoke('sync-ca', upgrade=remote.contract,
        public_ca=base64.b64encode(remote.new_ca).decode(), certificate_before=initial)['ca.pem']
    reverted = initial
    if generation == 'previous-after':
        cert = remote.ca_key.with_name('third.pem')
        subprocess.run(['openssl', 'req', '-x509', '-new', '-key', str(remote.ca_key), '-days', '1',
            '-subj', '/CN=iris', '-addext', 'subjectAltName=DNS:localhost', '-out', str(cert)],
            check=True, capture_output=True)
        remote.invoke('sync-ca', upgrade=remote.contract, public_ca=base64.b64encode(cert.read_bytes()).decode(),
                      certificate_before=after)
        reverted = after
    os.replace(remote.root / ('retained-' + reverted['sha256'] + '.pem'), remote.root / 'ca.pem')
    assert (remote.root / 'ca.pem').stat().st_ino == reverted['inode']
    remote.programs['current'] = remote.programs['original']
    result = remote.call('observe', checked=False)
    assert result.returncode != 0 and b'outside its intent' in result.stderr


@pytest.mark.parametrize('damage', ['foreign-key', 'foreign-issuer', 'substituted-before'])
def test_public_ca_transition_refuses_other_authority(remote, damage):
    remote.call('fence'); remote.call('publish')
    new = remote.ca_key.with_name('foreign.pem')
    if damage == 'foreign-key':
        key = remote.ca_key.with_name('foreign-key.pem')
        subprocess.run(['openssl', 'genrsa', '-out', str(key), '2048'], capture_output=True, check=True)
    else: key = remote.ca_key
    subprocess.run(['openssl', 'req', '-x509', '-new', '-key', str(key), '-days', '1',
        '-subj', '/CN=foreign' if damage == 'foreign-issuer' else '/CN=iris',
        '-addext', 'subjectAltName=DNS:localhost', '-out', str(new)], capture_output=True, check=True)
    before = dict(remote.contract['credentials']['ca.pem'])
    if damage == 'substituted-before': before['inode'] += 1
    old = (remote.root / 'ca.pem').read_bytes()
    result = remote.invoke('sync-ca', checked=False, upgrade=remote.contract,
        public_ca=base64.b64encode(new.read_bytes()).decode(), certificate_before=before)
    assert result.returncode != 0
    assert (remote.root / 'ca.pem').read_bytes() == old


def test_split_projection_matches_installation_transform_and_refuses_new_generation_drift(tmp_path, monkeypatch):
    old = {'name': 'owned', 'services': {'iris': {'environment': {'KEEP': 'server'}, 'ports': []},
        'console': {'build': {'context': 'old'}, 'depends_on': {'iris': {'condition': 'service_healthy'}},
            'environment': {'KEEP': 'console'}, 'volumes': ['old-volume:/run/old']}},
        'volumes': {'iris-state': {}}, 'networks': {'default': {'labels': {'com.cisco.iris.installer': INSTANCE}}}}
    install = SimpleNamespace(config=dict(target='docker-split', instance='owned', management_bind='192.0.2.1',
        console_ssh_host='192.0.2.2', console_state_dir='/etc/iris/console'),
        journal=SimpleNamespace(document={'id': INSTANCE}))
    projected = split.split_templates(install, old)
    assert set(projected['iris']['services']) == {'iris'}
    server = projected['iris']['services']['iris']
    assert server['environment']['IRIS_INSTALLER_TARGET'] == 'docker-split'
    assert server['ports'][-1]['published'] == '9443'
    console = projected['console']['services']['console']
    assert 'depends_on' not in console and 'build' not in console
    assert console['environment']['IRIS_MANAGEMENT_API_CA'] == '/run/iris-console-custody/ca.pem'
    assert console['volumes'][0]['read_only'] is True
    newer = copy.deepcopy(old); newer['services']['console']['environment']['NEW_RUNTIME_FIELD'] = 'not-migrated'
    new_projection = split.split_templates(install, newer)
    with pytest.raises(InstallError, match='runtime layout'):
        plan.candidate_compose(projected['console'], projected['console'], new_projection['console'],
                               {'console': NEW}, services=('console',))
    current = copy.deepcopy(projected['console']); current['services']['console']['environment']['OWNER_ROTATION'] = '/kept'
    result = plan.candidate_compose(current, projected['console'], projected['console'], {'console': NEW}, services=('console',))
    assert result['services']['console']['environment']['OWNER_ROTATION'] == '/kept'
