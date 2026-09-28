# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Installer-owned single-Docker trust cutover; no arbitrary paths or commands."""

import hashlib
import json
import uuid

from .state import InstallError, atomic_write, regular_bytes

FAMILIES = ('device-tls', 'peer-ca', 'instruction-roots')


def _one_shot(install, code, *arguments):
    source = "import sys; sys.path.insert(0,'/opt/iris/server'); " + code
    return install.compose('run', '--rm', '--no-deps', '-T', '--entrypoint', 'python3',
                           'iris', '-I', '-B', '-c', source, *arguments, capture=True)


def _stopped(install):
    ids = install.compose('ps', '--all', '--quiet', 'iris', 'console', capture=True).decode().split()
    if not ids:
        raise InstallError('Cannot prove deployment services are stopped')
    documents = json.loads(install.command(['docker', 'inspect', *ids], capture=True))
    transaction = getattr(install, 'credential_transaction', None)
    admitted_recovery = (getattr(install, 'credential_recovery', False) is True
        and transaction is not None and transaction.record.get('initial_clean_stop') is True)
    if any(item.get('State', {}).get('Running') is not False or (not admitted_recovery and
           (item['State'].get('OOMKilled') or item['State'].get('ExitCode') not in (0, 143))) for item in documents):
        raise InstallError('Cleanly stop every deployment writer before trust publication')


def _sync_roots(install, record):
    """Recoverable host root pin update; only exact old-or-approved bytes move."""
    transition_path = install.base / ('trust-roots-' + record['request_id'] + '.json')
    replacement = {name + '.pub': value.encode('ascii') for name, value in record['roots'].items()}
    digests = {name: hashlib.sha256(value).hexdigest() for name, value in replacement.items()}
    if transition_path.exists():
        transition = json.loads(regular_bytes(transition_path))
        if transition.get('after') != digests or not isinstance(transition.get('packages_before'), dict):
            raise InstallError('Approved host root transition changed')
    else:
        packages = install.journal.document['completed'].get('packages')
        if not isinstance(packages, dict):
            raise InstallError('Trust maintenance requires an established package checkpoint')
        transition = {'before': dict(install.journal.document['root_digests']), 'after': digests,
                      'packages_before': packages}
        atomic_write(transition_path, json.dumps(transition, sort_keys=True).encode())
    if set(transition['before']) != set(replacement):
        raise InstallError('Host root IDs differ from the approved transition')
    if install.journal.document['root_digests'] not in (transition['before'], transition['after']):
        raise InstallError('Installer root authority changed outside this transition')
    for name, public in replacement.items():
        path = install.base / 'roots' / name
        current = hashlib.sha256(regular_bytes(path)).hexdigest()
        if current not in (transition['before'][name], transition['after'][name]):
            raise InstallError('Host root changed outside the approved transition')
    for name, public in replacement.items():
        atomic_write(install.base / 'roots' / name, public, 0o644)
    install.journal.document['root_digests'] = digests
    # capture_plan requires the historical installed-package checkpoint even
    # when a failed rebuild removed it. Preserve this stopped ownership input;
    # finish always invalidates it before rebuilding or exposing the Console.
    install.journal.document['completed'].setdefault('packages', transition['packages_before'])
    install.journal.save()


def apply(install, kind, operation_id):
    if kind not in FAMILIES:
        raise InstallError('Unsupported trust maintenance family')
    _stopped(install)
    record = json.loads(_one_shot(install,
        'import trust_rotation,json; print(json.dumps(trust_rotation.apply_prepared(sys.argv[1],sys.argv[2])))',
        kind, operation_id))
    if record.get('state') != 'published' or record.get('request_id') != operation_id:
        raise InstallError('Trust publication did not produce matching evidence')
    if kind == 'instruction-roots':
        _sync_roots(install, record)
    return record


def pre_apply_check(install, kind, operation_id):
    _stopped(install)
    result = json.loads(_one_shot(install,
        'import trust_rotation,json; print(json.dumps(trust_rotation.check_prepared(sys.argv[1],sys.argv[2])))',
        kind, operation_id))
    if result != {'ready': True, 'family': kind, 'request_id': operation_id}:
        raise InstallError('Stopped trust admission did not return matching authority')


def recover_inputs(install, kind, operation_id):
    """Finish only a previously admitted public host-root pin transition."""
    if kind != 'instruction-roots':
        return
    transition = install.base / ('trust-roots-' + operation_id + '.json')
    if not transition.exists():
        return
    _stopped(install)
    record = json.loads(_one_shot(install,
        'import trust_rotation,json; print(json.dumps(trust_rotation.status(sys.argv[1])))', kind))
    if record.get('state') != 'published' or record.get('request_id') != operation_id or record.get('family') != kind:
        raise InstallError('Host root recovery has no matching published server approval')
    _sync_roots(install, record)


def finish(install, kind, operation_id):
    """After a fresh server start, verify packages and the effective trust.

    Deployment-neutral native packages need rebuilding only for root changes.
    ``packages`` reuses their checkpoint otherwise, and always refreshes and
    verifies the served Guest Shell bundle and distributed onboarding pin.
    """
    if kind == 'instruction-roots':
        if str(uuid.UUID(operation_id)) != operation_id:
            raise InstallError('Invalid trust operation identifier')
        # Public roots participate in the canonical image source fingerprint.
        # Keep the old-root archive intact and let the existing build verifier
        # create or verify this operation's new archive. Explicit same-ID
        # recovery selects the same path; never force past source/hash checks.
        install.env['IRIS_DEVICE_IMAGE_OCI'] = str(
            install.base / 'artifacts' / ('device-roots-' + operation_id + '.oci.tar'))
        install.journal.document['completed'].pop('packages', None)
        install.journal.document['completed'].pop('guestshell', None)
        install.journal.save()
    install.packages()
    code = '''
import hashlib,json,os,socket,ssl,time
from pathlib import Path
import instruction_keys as keys
import trust_rotation
kind, request_id = sys.argv[1:]
record = trust_rotation.status(kind)
if record['state'] != 'published' or record['request_id'] != request_id:
    raise RuntimeError('Trust request changed')
proof = {'family': kind, 'request_id': request_id, 'packages_verified': True,
         'device_consumers': 're-onboarding-required'}
if kind == 'device-tls':
    distributed = Path(os.environ.get('IRIS_ARTIFACTS_DIR','/srv/artifacts')) / 'iris-catalog.pem'
    context = ssl.create_default_context(cafile=str(distributed))
    host = record['names'][0]
    with socket.create_connection(('127.0.0.1',8443),timeout=10) as raw:
        with context.wrap_socket(raw,server_hostname=host) as secure:
            fingerprint = hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest()
    if fingerprint != record['fingerprint_sha256']:
        raise RuntimeError('Catalog is not serving the approved device identity')
    proof['catalog_tls_sha256'] = fingerprint
elif kind == 'peer-ca':
    import peer_tls_issuer,peer_tls_settings
    ca = peer_tls_issuer.Issuer().prepare()
    public = trust_rotation.tls._openssl('x509','-in',ca,'-outform','DER')
    if hashlib.sha256(public).hexdigest() != record['fingerprint_sha256']:
        raise RuntimeError('Peer issuer is not the approved identity')
    deadline = time.monotonic()+30
    while True:
        try:
            status = json.loads(Path(peer_tls_settings.status_path()).read_bytes())
        except (OSError,ValueError):
            status = {}
        if status.get('state') == 'running' and status.get('active_mode') == peer_tls_settings.mode() and abs(time.time()-status['updated_at']) < 30:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError('Origin has not adopted its replacement issuer')
        time.sleep(1)
    if status['active_mode'] == 'required':
        root = Path(os.environ.get('IRIS_RUN','/run/iris')) / 'peer-origin/peer-tls'
        generation = json.loads((root / 'current.json').read_bytes())['generation']
        if not isinstance(generation,str) or len(generation) != 64 or any(c not in '0123456789abcdef' for c in generation):
            raise RuntimeError('Invalid origin identity generation')
        ca = root / generation / 'ca.crt'
        leaf = root / generation / 'node.crt'
        public = trust_rotation.tls._openssl('x509','-in',ca,'-outform','DER')
        if hashlib.sha256(public).hexdigest() != record['fingerprint_sha256']:
            raise RuntimeError('Origin has retained a different peer issuer')
        trust_rotation.tls._openssl('verify','-CAfile',ca,leaf)
    proof['peer_ca_sha256'] = record['fingerprint_sha256']
    proof['origin_mode'] = status['active_mode']
else:
    paths = keys.InstructionPaths.from_env()
    roots = keys.discover_roots(paths)
    if roots != {name:value.encode('ascii') for name,value in record['roots'].items()}:
        raise RuntimeError('Runtime roots differ from approval')
    keys.validate_online_certificate(paths, paths.certificate, roots)
    snapshot = keys.read_keylist_snapshot(paths)
    if snapshot is None:
        raise RuntimeError('Replacement keylist is absent')
    proof['root_sha256'] = {name:hashlib.sha256(value).hexdigest() for name,value in roots.items()}
    proof['keylist_seq'] = snapshot['keylist_seq']
print(json.dumps(proof))
'''
    return json.loads(install.python(code, kind, operation_id))


def rotate(state_dir, backup_dir, recovery_dir, *, kind, operation_id, recovery_identity, recovery=False):
    from .credential_maintenance import Transaction
    return Transaction(state_dir, backup_dir, recovery_dir, kind=kind,
        operation_id=operation_id, recovery_identity=recovery_identity).run(
            apply, finish, recovery=recovery, pre_capture_recover=recover_inputs, pre_apply_check=pre_apply_check)
