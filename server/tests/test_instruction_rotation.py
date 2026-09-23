# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real age/OpenSSH rotation, crash recovery and preserved replay authority."""

import base64
import json
import importlib.util
from pathlib import Path
import shutil
import subprocess
import uuid

import pytest

import instruction_keys as keys
import instruction_rotation as rotation
from test_instruction_keys import _paths, _root_map, _root_public, _import_cert, _issue, _root_sign, NOW
from test_gui_server import _serve_full, _auth, _req
from test_api_split import policy_tiers


@pytest.fixture
def custody(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    roots = _root_map(tmp_path)
    identity = tmp_path / 'service.age'
    subprocess.run(['age-keygen', '-o', str(identity)], check=True, capture_output=True)
    recipient = subprocess.check_output(['age-keygen', '-y', str(identity)], text=True).strip()
    monkeypatch.setenv('IRIS_AGE_KEY_FILE', str(identity))
    monkeypatch.setenv('IRIS_AGE_RECIPIENTS', recipient)
    for name, value in [('IRIS_STATE', paths.state_dir), ('IRIS_CONFIG', paths.config_dir), ('IRIS_RUN', paths.run_dir)]:
        monkeypatch.setenv(name, value)
    keys.generate_online_key(paths, recipient)
    Path(paths.roots_dir).mkdir(parents=True)
    for name, path in _root_public(roots).items():
        (Path(paths.roots_dir) / (name + '.pub')).write_bytes(path.read_bytes())
    _import_cert(paths, _root_public(roots), roots['root-a'])
    Path(paths.epoch).write_bytes(b'unchanged epoch authority')
    (Path(paths.instructions_dir) / 'replay.fixture').write_bytes(b'unchanged serial floors')
    return paths, roots


def prepare(custody, tmp_path):
    paths, roots = custody
    result = rotation.prepare(str(uuid.uuid4()), paths=paths, now=NOW)
    public = tmp_path / 'replacement.pub'
    public.write_text(result['public_key'])
    certificate = _issue(roots['root-a'], public, NOW, NOW + 30 * 86400).read_text()
    return result, certificate


def retirement(custody, result):
    paths, roots = custody
    request = rotation.retirement_request(result['request_id'], 'root-a', paths=paths, now=NOW)
    payload = base64.b64decode(request['payload'])
    artifact = keys.assemble_keylist_artifact(payload, _root_sign(payload, roots['root-a']))
    return base64.b64encode(artifact).decode()


def test_real_rotation_retry_and_root_approved_retirement(custody, tmp_path):
    paths, roots = custody
    before = {path: path.read_bytes() for path in [Path(paths.epoch), Path(paths.instructions_dir) / 'replay.fixture']}
    old_public = Path(paths.public_key).read_bytes()
    old_signature = keys.sign_instruction(paths, b'payload', _root_public(roots), now=NOW)
    result, certificate = prepare(custody, tmp_path)
    assert Path(paths.public_key).read_bytes() == old_public
    assert rotation.prepare(result['request_id'], paths=paths, now=NOW) == result
    assert 'PRIVATE KEY' not in json.dumps(result)
    assert 'ciphertext' not in result
    active = rotation.activate(result['request_id'], certificate, paths=paths, now=NOW)
    assert active['state'] == 'retirement-pending'
    assert rotation.activate(result['request_id'], certificate, paths=paths, now=NOW) == active
    assert Path(paths.public_key).read_bytes() != old_public
    new_signature = keys.sign_instruction(paths, b'payload', _root_public(roots), now=NOW)
    approved = retirement(custody, result)
    done = rotation.retire(result['request_id'], approved, paths=paths, now=NOW)
    assert done['state'] == 'completed' and done['retired_keylist_seq'] == 1
    assert rotation.retire(result['request_id'], approved, paths=paths, now=NOW) == done
    for path, content in before.items():
        assert path.read_bytes() == content
    parsed = keys.parse_keylist_artifact(Path(paths.keylist_current).read_bytes())
    krl = tmp_path / 'retired.krl'
    krl.write_bytes(parsed['krl'])
    trust = tmp_path / 'allowed'
    keys.write_allowed_signers(trust, 'iris-server', list(_root_public(roots).values()),
                               namespace=keys.INSTRUCTION_NAMESPACE, certificate_authority=True)
    assert keys.verify_signature(b'payload', new_signature, trust, 'iris-server', keys.INSTRUCTION_NAMESPACE,
                                  krl=krl, verify_time=NOW)
    assert not keys.verify_signature(b'payload', old_signature, trust, 'iris-server', keys.INSTRUCTION_NAMESPACE,
                                      krl=krl, verify_time=NOW)


@pytest.mark.parametrize('boundary', ['encrypted_key', 'public_key', 'certificate', 'runtime_key', 'runtime_certificate', 'receipt'])
def test_interrupted_commit_recovers_before_signing(custody, tmp_path, monkeypatch, boundary):
    paths, roots = custody
    result, certificate = prepare(custody, tmp_path)
    original = keys._atomic_write
    failed = []
    target = str(rotation._path(paths)) if boundary == 'receipt' else str(getattr(paths, boundary))
    def fail_after(path, data, mode=0o600):
        original(path, data, mode=mode)
        if (str(path) == target and not failed
                and (boundary != 'receipt' or b'retirement-pending' in data)):
            failed.append(True)
            raise OSError('simulated durability boundary')
    monkeypatch.setattr(keys, '_atomic_write', fail_after)
    with pytest.raises(OSError):
        rotation.activate(result['request_id'], certificate, paths=paths, now=NOW)
    assert failed
    # Any signer/reader taking the custody lock finishes a committed intent.
    assert keys.sign_instruction(paths, b'after restart', _root_public(roots), now=NOW)
    assert rotation.status(paths)['state'] == 'retirement-pending'
    assert Path(paths.public_key).read_text() == result['public_key']
    assert Path(paths.epoch).read_bytes() == b'unchanged epoch authority'


def test_rejected_approval_and_cancel_leave_active_key_unchanged(custody, tmp_path):
    paths, roots = custody
    before = {path: Path(path).read_bytes() for path in [paths.public_key, paths.encrypted_key, paths.certificate]}
    result, certificate = prepare(custody, tmp_path)
    for bad in ['PRIVATE KEY', Path(paths.certificate).read_text()]:
        with pytest.raises(keys.InstructionKeyError):
            rotation.activate(result['request_id'], bad, paths=paths, now=NOW)
    with pytest.raises(keys.InstructionKeyError, match='existing rotation'):
        rotation.prepare(str(uuid.uuid4()), paths=paths, now=NOW)
    assert rotation.cancel(result['request_id'], paths=paths)['state'] == 'cancelled'
    with pytest.raises(keys.InstructionKeyError):
        rotation.activate(result['request_id'], certificate, paths=paths, now=NOW)
    for path, data in before.items():
        assert Path(path).read_bytes() == data


def test_stale_renewal_approval_cannot_switch_signer(custody, tmp_path):
    paths, roots = custody
    result, certificate = prepare(custody, tmp_path)
    prior = Path(paths.certificate).read_bytes()
    Path(paths.certificate).write_bytes(prior + b'\n')
    with pytest.raises(keys.InstructionKeyError, match='custody changed'):
        rotation.activate(result['request_id'], certificate, paths=paths, now=NOW)
    assert Path(paths.public_key).read_text() == result['previous_public_key']


def test_untrusted_retirement_never_changes_keylist(custody, tmp_path):
    paths, roots = custody
    result, certificate = prepare(custody, tmp_path)
    rotation.activate(result['request_id'], certificate, paths=paths, now=NOW)
    approved = retirement(custody, result)
    artifact = bytearray(base64.b64decode(approved))
    artifact[-10] = ord('A') if artifact[-10] != ord('A') else ord('B')
    with pytest.raises(keys.InstructionKeyError):
        rotation.retire(result['request_id'], base64.b64encode(artifact).decode(), paths=paths, now=NOW)
    assert not Path(paths.keylist_current).exists()


def test_retirement_preserves_existing_revocations_and_repairs_interruption(custody, tmp_path, monkeypatch):
    paths, roots = custody
    revoked = tmp_path / 'previously-revoked'
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(revoked)], check=True)
    krl = tmp_path / 'existing.krl'
    subprocess.run(['ssh-keygen', '-k', '-f', str(krl), str(revoked) + '.pub'], check=True, capture_output=True)
    payload = keys.build_keylist_payload(krl.read_bytes(), keylist_seq=7, issued_at=NOW, signer_root_id='root-a')
    keys.install_keylist(paths, keys.assemble_keylist_artifact(payload, _root_sign(payload, roots['root-a'])),
                         _root_public(roots), now=NOW)
    result, certificate = prepare(custody, tmp_path)
    rotation.activate(result['request_id'], certificate, paths=paths, now=NOW)
    approved = retirement(custody, result)
    original = keys._atomic_write_json
    def crash(path, value):
        if str(path) == paths.keylist_state:
            raise OSError('metadata interrupted')
        return original(path, value)
    monkeypatch.setattr(keys, '_atomic_write_json', crash)
    with pytest.raises(OSError):
        rotation.retire(result['request_id'], approved, paths=paths, now=NOW)
    assert rotation.status(paths)['state'] == 'retiring'
    monkeypatch.setattr(keys, '_atomic_write_json', original)
    assert rotation.retire(result['request_id'], approved, paths=paths, now=NOW)['retired_keylist_seq'] == 8
    parsed = keys.parse_keylist_artifact(Path(paths.keylist_current).read_bytes())
    krl.write_bytes(parsed['krl'])
    assert subprocess.run(['ssh-keygen', '-Q', '-f', str(krl), str(revoked) + '.pub'], capture_output=True).returncode == 1
    assert keys.sign_instruction(paths, b'after metadata repair', _root_public(roots), now=NOW)


@pytest.mark.parametrize('body', [None, {}, {'action': 'reset', 'request_id': 'x'},
    {'action': 'prepare', 'request_id': 'bad'}, {'action': 'prepare', 'request_id': str(uuid.uuid4()), 'root_key': 'no'},
    {'action': 'activate', 'request_id': str(uuid.uuid4()), 'confirm': 1, 'certificate': 'no'}])
def test_closed_public_contract(custody, body):
    with pytest.raises(keys.InstructionKeyError):
        rotation.operate(body, paths=custody[0], now=NOW)


def test_http_rotation_requires_owner_and_csrf(custody, tmp_path):
    host, port, _ctx, stop = _serve_full(tmp_path)
    endpoint = '/api/settings/certificates/instruction/rotation'
    try:
        assert _req(host, port, 'GET', endpoint)[0] == 401
        assert _req(host, port, 'POST', endpoint, body={})[0] == 401
        cookie, csrf = _auth(host, port)
        assert _req(host, port, 'POST', endpoint, body={}, headers={'Cookie': cookie})[0] == 403
        status, _, body = _req(host, port, 'GET', endpoint, headers={'Cookie': cookie})
        assert status == 200 and json.loads(body)['state'] == 'idle'
    finally:
        stop()


def test_rotation_through_console_and_authenticated_management(custody, policy_tiers, tmp_path, monkeypatch):
    paths, roots = custody
    request, _fleet, _store = policy_tiers
    original = rotation.operate
    monkeypatch.setattr(rotation, 'operate', lambda payload: original(payload, paths=paths, now=NOW))
    endpoint = '/settings/certificates/instruction/rotation'
    payload = {'action': 'prepare', 'request_id': str(uuid.uuid4())}
    for tier in ('console', 'management'):
        assert request(tier, 'GET', endpoint, authorized=False, match=False)[0] == 401
        assert request(tier, 'POST', endpoint, payload, authorized=False, match=False)[0] == 401
        status, headers, result = request(tier, 'POST', endpoint, payload, match=False)
        assert status == 200 and result['state'] == 'awaiting-approval'
        assert 'no-store' in headers['Cache-Control']
    public = tmp_path / 'approved.pub'
    public.write_text(result['public_key'])
    certificate = _issue(roots['root-a'], public, NOW, NOW + 30 * 86400).read_text()
    status, _, result = request('console', 'POST', endpoint, dict(payload, action='activate', certificate=certificate, confirm=True), match=False)
    assert status == 200 and result['state'] == 'retirement-pending'
    artifact = retirement(custody, result)
    status, _, result = request('console', 'POST', endpoint, dict(payload, action='retire', artifact=artifact, confirm=True), match=False)
    assert status == 200 and result['state'] == 'completed'


def test_offline_installer_approval_is_accepted(custody, tmp_path):
    paths, roots = custody
    result, certificate = prepare(custody, tmp_path)
    rotation.activate(result['request_id'], certificate, paths=paths, now=NOW)
    request = rotation.retirement_request(result['request_id'], 'root-a', paths=paths, now=NOW)
    payload, output = tmp_path / 'keylist.payload', tmp_path / 'keylist.envelope'
    payload.write_bytes(base64.b64decode(request['payload']))
    tool = Path(__file__).resolve().parents[2] / 'tools/irisctl'
    completed = subprocess.run([str(tool), 'approve-keylist', '--payload', str(payload),
        '--root-key', str(roots['root-a']), '--output', str(output)], capture_output=True)
    assert completed.returncode == 0, completed.stderr
    assert b'PRIVATE KEY' not in output.read_bytes()
    assert rotation.retire(result['request_id'], base64.b64encode(output.read_bytes()).decode(), paths=paths, now=NOW)['state'] == 'completed'


@pytest.mark.parametrize('architecture', ['amd64', 'arm64'])
def test_shared_device_verifier_accepts_replacement_rejects_retired(custody, tmp_path, architecture):
    """Native helper used by Guest Shell, IOx and XR; ARM executes under qemu."""
    repo = Path(__file__).resolve().parents[2]
    helper = repo / 'bin' / ('ssh-keygen-' + architecture)
    if not helper.is_file() or architecture == 'arm64' and not shutil.which('qemu-aarch64-static'):
        pytest.skip('Build the native SSHSIG helper and ARM emulation for this qualification')
    spec = importlib.util.spec_from_file_location('rotation_device_instr', repo / 'device/agent/instr.py')
    device = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(device)
    paths, roots = custody
    old = keys.sign_instruction(paths, b'rotation proof', _root_public(roots), now=NOW)
    result, certificate = prepare(custody, tmp_path)
    rotation.activate(result['request_id'], certificate, paths=paths, now=NOW)
    new = keys.sign_instruction(paths, b'rotation proof', _root_public(roots), now=NOW)
    rotation.retire(result['request_id'], retirement(custody, result), paths=paths, now=NOW)
    parsed = keys.parse_keylist_artifact(Path(paths.keylist_current).read_bytes())
    allowed = tmp_path / 'allowed'
    keys.write_allowed_signers(allowed, 'iris-server', list(_root_public(roots).values()),
        namespace=keys.INSTRUCTION_NAMESPACE, certificate_authority=True)
    root_allowed = tmp_path / 'root-allowed'
    root_allowed.write_bytes(b''.join(b'iris-root:' + name.encode() + b' namespaces="iris-keylist-v1" ' +
        b' '.join(path.read_bytes().split()[:2]) + b'\n' for name, path in _root_public(roots).items()))
    def runner(command, **kwargs):
        return subprocess.run((['qemu-aarch64-static'] if architecture == 'arm64' else []) + command, **kwargs)
    verifier = device.SSHVerifier(str(helper), str(allowed), str(root_allowed), str(tmp_path / 'verify'), runner=runner)
    assert verifier.verify(parsed['payload'], parsed['signature'], keys.KEYLIST_NAMESPACE, 'iris-root:root-a', NOW)
    assert verifier.verify(b'rotation proof', new, keys.INSTRUCTION_NAMESPACE, 'iris-server', NOW, krl=parsed['krl'])
    assert not verifier.verify(b'rotation proof', old, keys.INSTRUCTION_NAMESPACE, 'iris-server', NOW, krl=parsed['krl'])


def test_real_producer_reissues_after_rotation_without_reset(custody, tmp_path):
    import catalog
    import instruction_stamper as stamper
    import peer_policy
    import secrets_store
    from test_instruction_stamper import Fleet, _record

    paths, roots = custody
    # This test establishes an actual producer in place of the sentinel epoch.
    Path(paths.epoch).unlink()
    producer_paths = stamper.StamperPaths(paths.state_dir, paths.config_dir, paths.run_dir, str(tmp_path / 'secrets.json'))
    secrets_store.save({'devices': {'rotation-device': {'instr_key': _record()}}, 'seeder': {}}, producer_paths.secrets)
    fleet = Fleet([{'device_id': 'rotation-device', 'platform': 'guestshell', 'registered_at': NOW - 20}])
    cat = catalog.CatalogStore(paths.state_dir)
    peer_policy.initialize(producer_paths.policy_authoritative, producer_paths.policy_lkg)
    marker = stamper.initialize_producer('initialize', paths=producer_paths, fleet=fleet, now=lambda: NOW)
    producer = stamper.InstructionStamper(paths=producer_paths, fleet=fleet, catalog_store=cat, now=lambda: NOW)
    assert producer.stamp_device('rotation-device') == 'updated'
    previous = dict(cat._policies.get('rotation-device')['instr'])
    state_before = {path: Path(path).read_bytes() for path in (paths.epoch, producer_paths.activation, producer_paths.secrets)}
    result, certificate = prepare(custody, tmp_path)
    rotation.activate(result['request_id'], certificate, paths=paths, now=NOW)
    rotation.retire(result['request_id'], retirement(custody, result), paths=paths, now=NOW)
    assert producer.stamp_device('rotation-device') == 'updated'
    current = cat._policies.get('rotation-device')['instr']
    assert current['epoch'] == previous['epoch'] == marker['epoch']
    assert current['instr_serial'] > previous['instr_serial']
    assert current['key_id'] == previous['key_id']
    assert current['role_gen'] != previous['role_gen']
    assert producer.stamp_device('rotation-device') == 'unchanged'
    assert all(Path(path).read_bytes() == value for path, value in state_before.items())


def test_changed_retirement_request_cannot_receive_another_requests_receipt(custody, tmp_path, monkeypatch):
    paths, roots = custody
    result, certificate = prepare(custody, tmp_path)
    rotation.activate(result['request_id'], certificate, paths=paths, now=NOW)
    approved = retirement(custody, result)
    original = keys.install_keylist
    def concurrent(*args, **kwargs):
        rotation.retirement_request(result['request_id'], 'root-b', paths=paths, now=NOW)
        return original(*args, **kwargs)
    monkeypatch.setattr(keys, 'install_keylist', concurrent)
    with pytest.raises(keys.InstructionKeyError, match='request changed during publication'):
        rotation.retire(result['request_id'], approved, paths=paths, now=NOW)
    assert rotation.status(paths)['state'] == 'retirement-pending'
    monkeypatch.setattr(keys, 'install_keylist', original)
    fresh = retirement(custody, result)
    assert rotation.retire(result['request_id'], fresh, paths=paths, now=NOW)['retired_keylist_seq'] == 2
