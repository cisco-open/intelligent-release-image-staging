# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real crypto custody tests and isolated Docker orchestration fault injection."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import credential_maintenance as cm
from iris_installer.state import InstallError, atomic_write


class CryptoInstall:
    def __init__(self, base):
        self.base = base
        self.compose_file = base / 'compose.json'
        self.calls = []
        self.journal = SimpleNamespace(document={'completed': {}}, save=lambda: None)

    def command(self, args, *, input=None, capture=False, **kwargs):
        result = subprocess.run(list(map(str, args)), input=input, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=True)
        return result.stdout if capture else b''

    def compose(self, *args, **kwargs):
        self.calls.append(args)
        return b''


@pytest.fixture
def crypto(tmp_path, monkeypatch):
    if not shutil.which('age') or not shutil.which('age-keygen'):
        pytest.skip('age executables required for independent cryptographic tests')
    install = CryptoInstall(tmp_path)
    recovery = tmp_path / 'recovery'
    service = tmp_path / 'age.txt'
    for path in (recovery, service):
        atomic_write(path, install.command(['age-keygen'], capture=True))
    recipients = [install.command(['age-keygen', '-y', p], capture=True).decode().strip()
                  for p in (service, recovery)]
    install.config = {'recovery_recipient': recipients[1], 'host': '192.0.2.42', 'instance': 'test'}
    install.journal.document['config'] = install.config
    atomic_write(install.compose_file, json.dumps({'services': {'iris': {'environment': {
        'IRIS_AGE_RECIPIENTS': ','.join(recipients)}}}}).encode())
    config = tmp_path / 'config'
    (config / 'tls').mkdir(parents=True)
    plain = b'recovery-critical-secret-do-not-log'
    for name in ('secrets.json.age', 'rpc-secret.age', 'tls/key.pem.age',
                 'tls/console-fallback.pem.age', 'tls/management-key.pem.age'):
        atomic_write(config / name, cm._encrypt(install, plain, recipients))
    tx = object.__new__(cm.Transaction)
    tx.base, tx.identity, tx.install = tmp_path, recovery, install
    tx.kind, tx.id = 'age-identity', str(uuid.uuid4())
    tx.directory = tmp_path / 'operation'
    tx.directory.mkdir(mode=0o700)
    tx.pointer = tmp_path / 'credential-operation.json'
    tx.record = {'kind': tx.kind, 'operation_id': tx.id}
    tx.sources = {'volume-iris-config': config}
    install.credential_transaction = tx
    # Metadata semantics are covered separately; non-root tests cannot chown
    # the two newly created service-owned management files.
    monkeypatch.setattr(cm.os, 'chown', lambda *args: None)
    return install, tx, plain, recipients


def test_age_rotates_every_cipher_preserves_recovery_and_encrypts_candidates(crypto):
    install, tx, plain, recipients = crypto
    old = (install.base / 'age.txt').read_bytes()
    cm._age_apply(install, tx.kind, tx.id)
    assert (install.base / 'age.txt').read_bytes() != old
    assert tx.record['age_files'] == 5
    assert tx.record['service_recipient'] != recipients[0]
    for path in tx.sources['volume-iris-config'].rglob('*.age'):
        assert cm._decrypt(install, path.read_bytes(), install.base / 'age.txt') == plain
        assert cm._decrypt(install, path.read_bytes(), tx.identity) == plain
    for candidate in tx.directory.glob('candidate-*.age'):
        assert plain not in candidate.read_bytes()
        assert b'AGE-SECRET-KEY-' not in candidate.read_bytes()
    assert b'AGE-SECRET-KEY-' not in tx.pointer.read_bytes()
    assert any('trust_rotation' in str(call) for call in install.calls)


def test_age_recovery_rolls_forward_partially_written_identity_and_compose(crypto, monkeypatch):
    install, tx, plain, _ = crypto
    original = cm.atomic_write
    writes = 0
    def interrupted(path, value, mode=0o600):
        nonlocal writes
        if Path(path).is_relative_to(tx.sources['volume-iris-config']):
            writes += 1
            if writes == 3:
                raise OSError('simulated power loss')
        original(path, value, mode)
    monkeypatch.setattr(cm, 'atomic_write', interrupted)
    with pytest.raises(OSError):
        cm._age_apply(install, tx.kind, tx.id)
    assert (tx.directory / 'write-plan.json').is_file()
    monkeypatch.setattr(cm, 'atomic_write', original)
    cm._age_apply(install, tx.kind, tx.id)
    for path in tx.sources['volume-iris-config'].rglob('*.age'):
        assert cm._decrypt(install, path.read_bytes(), install.base / 'age.txt') == plain
    assert install.journal.document['completed']['prepared'] == cm.digest(install.compose_file)


def test_age_recovery_preserves_post_restart_state_updates(crypto):
    install, tx, _, _ = crypto
    cm._age_apply(install, tx.kind, tx.id)
    path = tx.sources['volume-iris-config'] / 'secrets.json.age'
    fresh = b'new-legitimate-post-restart-state'
    recipients = [tx.record['service_recipient'], install.config['recovery_recipient']]
    atomic_write(path, cm._encrypt(install, fresh, recipients))
    cm._age_apply(install, tx.kind, tx.id)
    assert cm._decrypt(install, path.read_bytes(), tx.identity) == fresh


def test_age_refuses_current_state_without_independent_recipient(crypto):
    install, tx, plain, recipients = crypto
    path = tx.sources['volume-iris-config'] / 'secrets.json.age'
    atomic_write(path, cm._encrypt(install, plain, [recipients[0]]))
    original_identity = (install.base / 'age.txt').read_bytes()
    with pytest.raises(subprocess.CalledProcessError):
        cm._age_apply(install, tx.kind, tx.id)
    assert (install.base / 'age.txt').read_bytes() == original_identity
    assert not (tx.directory / 'write-plan.json').exists()


def test_age_refuses_symlink_ciphertext(crypto):
    install, tx, _, _ = crypto
    (tx.sources['volume-iris-config'] / 'link.age').symlink_to(tx.identity)
    with pytest.raises(InstallError, match='symbolic'):
        cm._age_apply(install, tx.kind, tx.id)


def approve_recovery(install, tx):
    replacement = install.base / 'replacement-identity'
    atomic_write(replacement, install.command(['age-keygen'], capture=True))
    public = install.command(['age-keygen', '-y', replacement], capture=True).decode().strip()
    atomic_write(install.base / 'recovery-candidate.json', json.dumps({
        'operation_id': tx.id, 'identity_path': str(replacement), 'recipient': public}).encode())
    tx.kind = 'age-recovery'
    return replacement, public


def test_recovery_recipient_preserves_service_identity_and_old_backup_custody(crypto):
    install, tx, plain, old_recipients = crypto
    replacement, public = approve_recovery(install, tx)
    service_bytes = (install.base / 'age.txt').read_bytes()
    cm._recovery_apply(install, tx.kind, tx.id)
    assert (install.base / 'age.txt').read_bytes() == service_bytes
    assert install.config['recovery_recipient'] == public
    for path in tx.sources['volume-iris-config'].rglob('*.age'):
        assert cm._decrypt(install, path.read_bytes(), replacement) == plain
        assert cm._decrypt(install, path.read_bytes(), install.base / 'age.txt') == plain
        with pytest.raises(subprocess.CalledProcessError):
            cm._decrypt(install, path.read_bytes(), tx.identity)
    # The interrupted-operation plan intentionally remains in OLD custody.
    for candidate in tx.directory.glob('candidate-*.age'):
        assert cm._decrypt(install, candidate.read_bytes(), tx.identity)
        with pytest.raises(subprocess.CalledProcessError):
            cm._decrypt(install, candidate.read_bytes(), replacement)
    cm._recovery_apply(install, tx.kind, tx.id)
    assert install.config['recovery_recipient'] == public


def test_recovery_recipient_rolls_forward_after_partial_cipher_writes(crypto, monkeypatch):
    install, tx, plain, recipients = crypto
    replacement, public = approve_recovery(install, tx)
    original = cm.atomic_write
    writes = 0
    def interrupted(path, value, mode=0o600):
        nonlocal writes
        if Path(path).is_relative_to(tx.sources['volume-iris-config']):
            writes += 1
            if writes == 2:
                raise OSError('power loss')
        original(path, value, mode)
    monkeypatch.setattr(cm, 'atomic_write', interrupted)
    with pytest.raises(OSError):
        cm._recovery_apply(install, tx.kind, tx.id)
    assert install.config['recovery_recipient'] == recipients[1]
    monkeypatch.setattr(cm, 'atomic_write', original)
    cm._recovery_apply(install, tx.kind, tx.id)
    assert install.config['recovery_recipient'] == public
    for path in tx.sources['volume-iris-config'].rglob('*.age'):
        assert cm._decrypt(install, path.read_bytes(), replacement) == plain


@pytest.mark.parametrize('change', ['operation', 'recipient', 'permissions', 'identity'])
def test_recovery_recipient_rejects_unapproved_custody(crypto, change):
    install, tx, _, _ = crypto
    replacement, _ = approve_recovery(install, tx)
    path = install.base / 'recovery-candidate.json'
    candidate = json.loads(path.read_bytes())
    if change == 'operation':
        candidate['operation_id'] = str(uuid.uuid4())
    elif change == 'recipient':
        candidate['recipient'] = install.config['recovery_recipient']
    elif change == 'identity':
        candidate['identity_path'] = str(install.base / 'age.txt')
        candidate['recipient'] = install.command(['age-keygen', '-y', install.base / 'age.txt'], capture=True).decode().strip()
    atomic_write(path, json.dumps(candidate).encode(), 0o644 if change == 'permissions' else 0o600)
    with pytest.raises(InstallError):
        cm._recovery_apply(install, tx.kind, tx.id)
    assert not (tx.directory / 'write-plan.json').exists()


def test_management_key_is_independent_and_recoverable(crypto):
    install, tx, _, _ = crypto
    tx.kind = 'management-tls'
    original_device = (tx.sources['volume-iris-config'] / 'tls/key.pem.age').read_bytes()
    cm._management_apply(install, tx.kind, tx.id)
    cipher = (tx.sources['volume-iris-config'] / 'tls/management-key.pem.age').read_bytes()
    private = cm._decrypt(install, cipher, tx.identity)
    assert private.startswith(b'-----BEGIN PRIVATE KEY-----')
    assert cm._decrypt(install, cipher, install.base / 'age.txt') == private
    assert (tx.sources['volume-iris-config'] / 'tls/key.pem.age').read_bytes() == original_device
    assert len(tx.record['expected_management_sha256']) == 64
    assert b'PRIVATE KEY' not in tx.pointer.read_bytes()
    before = cipher
    cm._management_apply(install, tx.kind, tx.id)
    assert (tx.sources['volume-iris-config'] / 'tls/management-key.pem.age').read_bytes() == before


def test_candidate_plan_cannot_escape_storage(crypto, tmp_path):
    install, tx, _, _ = crypto
    outside = tmp_path.parent / 'not-an-owned-credential'
    with pytest.raises(InstallError, match='escapes'):
        tx.stage([(outside, b'value', 0o600, 0, 0)])


def test_candidate_plan_refuses_external_file_mutation(crypto):
    install, tx, _, _ = crypto
    target = install.base / 'public-file'
    atomic_write(target, b'before')
    tx.stage([(target, b'after', 0o600, 0, 0)])
    atomic_write(target, b'external mutation')
    with pytest.raises(InstallError, match='outside'):
        tx.apply_plan()
    assert target.read_bytes() == b'external mutation'


def test_compose_checkpoint_recovers_only_exact_approved_bytes(crypto):
    install, tx, _, _ = crypto
    before = cm.digest(install.compose_file)
    tx.stage([(install.compose_file, b'approved new compose', 0o600, 0, 0)])
    install.journal.document['completed']['prepared'] = before
    atomic_write(install.compose_file, b'approved new compose')
    tx._reconcile_compose(install)
    assert install.journal.document['completed']['prepared'] == cm.digest(install.compose_file)
    atomic_write(install.compose_file, b'unapproved')
    with pytest.raises(InstallError, match='differs'):
        tx._reconcile_compose(install)


@pytest.mark.parametrize('running,exit_code,oom', [(True, 0, False), (False, 137, False), (False, 0, True)])
def test_freeze_rejects_running_killed_or_oom_writer(running, exit_code, oom):
    install = SimpleNamespace(command=lambda *args, **kwargs: json.dumps([{'State': {
        'Running': running, 'ExitCode': exit_code, 'OOMKilled': oom}}]).encode())
    with pytest.raises(InstallError, match='cleanly stopped'):
        cm._stop(install, [{'id': 'owned'}])


def test_memory_scratch_requires_verified_tmpfs():
    install = SimpleNamespace(command=lambda *args, **kwargs: b'ext4\n')
    with pytest.raises(InstallError, match='memory-backed'):
        with cm._memory(install):
            pytest.fail('must not decrypt')


def test_private_recovery_identity_rejects_public_permissions(tmp_path):
    identity = tmp_path / 'identity'
    identity.write_bytes(b'private')
    identity.chmod(0o644)
    with pytest.raises(InstallError, match='custody'):
        cm._safe_file(identity, private=True)


def test_runtime_scripts_never_disable_tls_or_claim_without_live_proof():
    assert 'make_swarm_probe' in cm._SEEDER_SCRIPT
    assert "r.main(['--maintenance-frozen'" in cm._SEEDER_SCRIPT
    assert 'fingerprint() == sys.argv[2]' in cm._SEEDER_SCRIPT
    assert 'check-certificate=false' not in cm._SEEDER_SCRIPT
    assert 'verify=False' not in cm._SEEDER_SCRIPT


def test_public_dispatch_refuses_unknown_family_before_work():
    with pytest.raises(InstallError, match='Unsupported'):
        cm.rotate('/', '/', '/', kind='arbitrary-shell', operation_id='bad', recovery_identity=None)


@pytest.fixture
def orchestrator(tmp_path, monkeypatch):
    events = []
    state, backups, recovery = [tmp_path / name for name in ('state', 'backups', 'recovery')]
    for directory in (state, backups, recovery):
        directory.mkdir(mode=0o700)
    identity = tmp_path / 'offline-identity'
    identity.write_bytes(b'fixture')
    identifier = str(uuid.uuid4())
    document = {'id': 'installation-id', 'completed': {},
                'config': {'recovery_recipient': 'recovery-public', 'instance': 'test'}}
    class Journal:
        def __init__(self, base):
            self.directory, self.document = base, document
        @contextmanager
        def locked(self):
            yield self
        def save(self):
            events.append('journal-save')
    class Install:
        def __init__(self, journal):
            self.journal, self.base, self.config = journal, state, document['config']
            self.compose_file = state / 'compose.json'
        def command(self, args, **kwargs):
            assert args[:2] == ['age-keygen', '-y']
            return b'recovery-public' if args[-1] == identity else b'service-public'
        def compose(self, *args, **kwargs):
            events.append('compose:' + args[0] + ':' + args[-1])
        def verify_resource_ownership(self):
            events.append('ownership')
    def capture(install):
        events.append('capture-plan')
        return {}, {}, [{'id': 'console'}, {'id': 'server'}]
    def create(args):
        events.append('cold-backup')
        Path(args.output).mkdir()
        Path(args.recovery_output).mkdir()
    def read(path, *args):
        if not path.exists():
            raise InstallError('partial backup')
        events.append('verify-backup')
        return {'metadata': {'instance_id': 'installation-id', 'backup_set_id': 'pair',
                'target': 'single-docker',
                'scope': 'managed-deployment-files' if path.parent == backups else 'identity-recovery'}}
    def consumer(install):
        events.append('consumer-proof')
        return {'management_https': 'verified', 'certificate_sha256': '1' * 64}
    monkeypatch.setattr(cm.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(cm.backup_archive, 'private_directory', lambda p: Path(p))
    monkeypatch.setattr(cm, '_safe_file', lambda *args, **kwargs: None)
    monkeypatch.setattr(cm, 'Journal', Journal)
    monkeypatch.setattr(cm, 'DockerInstall', Install)
    monkeypatch.setattr(cm, '_pin_runtime', lambda install: None)
    monkeypatch.setattr(cm.backup, 'create', create)
    monkeypatch.setattr(cm.backup, 'capture_plan', capture)
    monkeypatch.setattr(cm.backup_archive, 'read', read)
    monkeypatch.setattr(cm, '_stop', lambda *args, **kwargs: events.append('clean-stop-proof'))
    monkeypatch.setattr(cm, '_consumer_proof', consumer)
    tx = cm.Transaction(state, backups, recovery, kind='age-identity',
                        operation_id=identifier, recovery_identity=identity)
    return tx, events


def test_transaction_backup_freeze_restart_consumer_order_and_idempotency(orchestrator):
    tx, events = orchestrator
    def apply(*args):
        events.append('apply')
    def finish(*args):
        events.append('finish')
        return {'service': 'verified'}
    result = tx.run(apply, finish)
    assert result['state'] == 'rotated'
    assert events == ['cold-backup', 'verify-backup', 'verify-backup', 'capture-plan',
                      'clean-stop-proof', 'apply', 'compose:up:iris', 'finish',
                      'compose:up:console', 'consumer-proof']
    events.clear()
    assert tx.run(apply, finish) == result
    assert events == []


def test_transaction_failure_stays_stopped_requires_explicit_same_id_recovery(orchestrator):
    tx, events = orchestrator
    def fail(*args):
        raise InstallError('simulated apply failure')
    with pytest.raises(InstallError, match='simulated'):
        tx.run(fail, lambda *args: {})
    assert events[-2:] == ['ownership', 'compose:stop:iris']
    assert json.loads(tx.pointer.read_bytes())['phase'] == 'recovery-required'
    with pytest.raises(InstallError, match='explicit'):
        tx.run(lambda *args: None, lambda *args: {})
    events.clear()
    result = tx.run(lambda *args: events.append('apply'), lambda *args: {}, recovery=True,
                    pre_capture_recover=lambda *args: events.append('recover-inputs'))
    assert result['state'] == 'rotated'
    assert 'cold-backup' not in events
    assert events.index('compose:stop:iris') < events.index('recover-inputs') < events.index('capture-plan')


def test_transaction_bad_backup_never_mutates_credentials(orchestrator, monkeypatch):
    tx, events = orchestrator
    def bad_backup(*args):
        raise InstallError('decryption failed')
    monkeypatch.setattr(cm.backup_archive, 'read', bad_backup)
    with pytest.raises(InstallError, match='decryption'):
        tx.run(lambda *args: pytest.fail('must not write'), lambda *args: {})
    assert events == ['cold-backup']


@pytest.mark.parametrize('scope,target', [('identity-recovery', 'single-docker'),
    ('managed-deployment-files', 'single-docker'), ('managed-deployment-files', 'other-layout')])
def test_backup_proof_rejects_duplicate_scopes_or_wrong_topology(orchestrator, monkeypatch, scope, target):
    tx, events = orchestrator
    monkeypatch.setattr(cm.backup_archive, 'read', lambda *args: {'metadata': {
        'instance_id': 'installation-id', 'backup_set_id': 'pair', 'scope': scope, 'target': target}})
    with pytest.raises(InstallError, match='Recovery sets'):
        tx.run(lambda *args: pytest.fail('wrong backup scope cannot authorize mutation'), lambda *args: {})
    assert events == ['cold-backup']


def test_stopped_readonly_refusal_restores_verified_consumers_before_terminal_refusal(orchestrator):
    tx, events = orchestrator
    def refuse(*args):
        events.append('readonly-check')
        raise InstallError('a new pending trust approval')
    with pytest.raises(InstallError, match='original services verified'):
        tx.run(lambda *args: pytest.fail('no credential mutation admitted'), lambda *args: {},
               pre_apply_check=refuse)
    assert tx.record['phase'] == 'refused'
    assert tx.record['mutations_admitted'] is False
    assert events[-4:] == ['readonly-check', 'compose:up:iris', 'compose:up:console', 'consumer-proof']
    with pytest.raises(InstallError, match='start a new'):
        tx.run(lambda *args: None, lambda *args: {}, recovery=True)


def test_stopped_refusal_failed_consumer_proof_remains_recovery_required(orchestrator, monkeypatch):
    tx, events = orchestrator
    def refuse(*args):
        raise InstallError('pending')
    monkeypatch.setattr(cm, '_consumer_proof', refuse)
    with pytest.raises(InstallError):
        tx.run(lambda *args: pytest.fail('no writes'), lambda *args: {}, pre_apply_check=refuse)
    assert tx.record['phase'] == 'recovery-required'
    assert tx.record['mutations_admitted'] is False
    assert events[-2:] == ['ownership', 'compose:stop:iris']


def test_interrupted_admitted_operation_never_uses_preflight_refusal_resume(orchestrator):
    tx, events = orchestrator
    def fail(*args):
        raise InstallError('write interrupted')
    with pytest.raises(InstallError):
        tx.run(fail, lambda *args: {})
    assert tx.record['mutations_admitted'] is True
    with pytest.raises(InstallError, match='write interrupted'):
        tx.run(fail, lambda *args: {}, recovery=True,
               pre_apply_check=lambda *args: pytest.fail('do not treat admitted writes as read-only refusal'))
    assert tx.record['phase'] == 'recovery-required'


def test_seeder_admission_failure_creates_no_intent_or_downtime(orchestrator):
    tx, events = orchestrator
    def refuse(*args):
        raise InstallError('publish first')
    with pytest.raises(InstallError, match='publish first'):
        tx.run(lambda *args: None, lambda *args: {}, preflight=refuse)
    assert not (tx.directory / 'record.json').exists()
    assert not tx.pointer.exists()
    assert events == []


def test_explicit_repair_can_admit_stopped_failed_restart_but_not_live_writer():
    state = {'Running': False, 'ExitCode': 1, 'OOMKilled': False}
    install = SimpleNamespace(command=lambda *args, **kwargs: json.dumps([{'State': state}]).encode())
    with pytest.raises(InstallError):
        cm._stop(install, [{'id': 'owned'}])
    cm._stop(install, [{'id': 'owned'}], recovering_clean_operation=True)
    state['Running'] = True
    with pytest.raises(InstallError):
        cm._stop(install, [{'id': 'owned'}], recovering_clean_operation=True)


def test_seeder_readiness_failure_is_fixed_nonsecret_message():
    def refuse(*args):
        raise RuntimeError('untrusted server exception with secret')
    with pytest.raises(InstallError, match='published, actively seeded artifact') as error:
        cm._seeder_preflight(SimpleNamespace(python=refuse, compose=lambda *a, **kw: b''), 'seeder-announce', str(uuid.uuid4()))
    assert 'secret' not in str(error.value)


def test_recipient_transition_recovers_with_original_identity_after_config_commit(orchestrator):
    tx, events = orchestrator
    tx.kind = 'age-recovery'
    def apply(install, *args):
        install.config['recovery_recipient'] = 'approved-new-recipient'
    def failed_proof(*args):
        raise InstallError('restart proof failed')
    with pytest.raises(InstallError, match='proof'):
        tx.run(apply, failed_proof)
    result = tx.run(apply, lambda *args: {'recovery_recipient': 'approved-new-recipient'}, recovery=True)
    assert result['state'] == 'rotated'
    # Worker may crash after this commit but BEFORE switching its active key.
    # Its pinned original operation identity can retrieve the terminal result.
    assert tx.run(apply, failed_proof, recovery=True) == result


def test_transaction_partial_backup_recovery_preserves_old_attempt_recaptures_new_pair(orchestrator):
    tx, events = orchestrator
    tx.directory.parent.mkdir()
    tx.directory.mkdir()
    tx.record = {'kind': tx.kind, 'operation_id': tx.id, 'phase': 'backup-pending',
                 'instance_id': 'installation-id'}
    tx.save('backup-pending')
    (tx.recoveries / tx.id).mkdir()
    result = tx.run(lambda *args: None, lambda *args: {}, recovery=True)
    assert result['state'] == 'rotated'
    assert 'cold-backup' in events
    assert (tx.recoveries / tx.id).is_dir()
    assert not (tx.backups / tx.id).exists()
    assert tx.record['abandoned_backup_ids'] == [tx.id]
    assert result['backup_id'] != tx.id
    assert (tx.backups / result['backup_id']).is_dir()
    assert (tx.recoveries / result['backup_id']).is_dir()


def test_seeder_maintenance_isolated_network_no_ports_only_tracker_mode(crypto, monkeypatch):
    install, tx, _, recipients = crypto
    tx.kind = 'seeder-announce'
    install.journal.document['id'] = 'installer-id'
    compose = json.loads(install.compose_file.read_bytes())
    compose['services']['iris'].update(image='pinned-image', ports=[{'published': 6969}],
        build={'context': 'source'}, restart='unless-stopped',
        labels={'com.cisco.iris.installer': 'installer-id'})
    install.journal.document['completed']['images'] = {'pinned-image': 'sha256:' + 'b' * 64}
    compose['services']['console'] = {'image': 'console'}
    compose['volumes'] = {'iris-config': {'name': 'owned-config'}}
    atomic_write(install.compose_file, json.dumps(compose).encode())
    value = json.dumps({'seeder': {'announce_token': {'value': 'secret-seeder-token'}}}).encode()
    atomic_write(tx.sources['volume-iris-config'] / 'secrets.json.age', cm._encrypt(install, value, recipients))
    hashes = ['a' * 40]
    install.compose = lambda *args, **kwargs: json.dumps(hashes).encode() if kwargs.get('capture') else b''
    commands = []
    def maintenance(install, tx, *args, **kwargs):
        commands.append(args)
        return json.dumps({'info_hashes': hashes, 'credential_changed': True, 'isolated_tracker_proof': True}).encode()
    monkeypatch.setattr(cm, '_maintenance_command', maintenance)
    monkeypatch.setattr(cm, '_maintenance_cleanup', lambda *args: commands.append(('cleanup',)))
    cm._seeder_apply(install, tx.kind, tx.id)
    actual = json.loads((tx.directory / 'maintenance.json').read_bytes())
    assert set(actual['services']) == {'iris'}
    spec = actual['services']['iris']
    assert spec['ports'] == [] and spec['restart'] == 'no'
    assert spec['image'] == 'sha256:' + 'b' * 64
    assert spec['networks'] == ['maintenance']
    assert actual['networks']['maintenance']['internal'] is True
    assert actual['volumes']['iris-config'] == {'external': True, 'name': 'owned-config'}
    assert spec['environment']['IRIS_MAINTENANCE_SEEDER_ONLY'] == '1'
    assert spec['environment']['IRIS_TELEMETRY_CA'] == '/run/iris/tls/maintenance-crt.pem'
    assert commands[-1] == ('cleanup',)
    assert b'secret-seeder-token' not in tx.pointer.read_bytes()


def test_all_runtime_compose_calls_use_recorded_immutable_images(crypto):
    install, tx, _, _ = crypto
    specification = json.loads(install.compose_file.read_bytes())
    specification['services']['iris'].update(image='mutable-tag', build={'context': 'source'})
    atomic_write(install.compose_file, json.dumps(specification).encode())
    original = install.compose_file.read_bytes()
    install.journal.document['completed']['images'] = {'mutable-tag': 'sha256:' + '1' * 64}
    checks = []
    install.build = lambda: checks.append('validated tag')
    seen = []
    def command(args, **kwargs):
        runtime = Path(args[args.index('-f') + 1])
        seen.append(runtime)
        value = json.loads(runtime.read_bytes())['services']['iris']
        assert value['image'] == 'sha256:' + '1' * 64
        assert 'build' not in value
        assert kwargs == {'capture': True}
        return b'proof'
    install.command = command
    cm._pin_runtime(install)
    assert install.compose('run', '--rm', '--no-deps', 'iris', 'true', capture=True) == b'proof'
    assert checks == ['validated tag']
    assert all(not path.exists() for path in seen)
    assert install.compose_file.read_bytes() == original
