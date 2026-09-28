# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Concrete helper transport and topology-dispatch safety checks."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import backup, credential_maintenance as cm, topology_lifecycle as tl
from iris_installer import trust_maintenance as trust
from iris_installer import kube_credentials
from iris_installer.state import InstallError


@pytest.fixture
def helper(tmp_path):
    source = tmp_path / 'source'
    source.mkdir(mode=0o700)
    destination = tmp_path / 'snapshots'
    destination.mkdir(mode=0o700)
    calls = []

    def run(argv, *, input=None, capture=False):
        assert capture
        assert argv[:4] == ['python3', '-I', '-B', '-c']
        calls.append(argv)
        argv = list(argv)
        argv[4] = argv[4].replace('/data/images', str(source))
        assert argv[5] == '/data/images'
        argv[5] = str(source)
        return subprocess.check_output(argv, input=input, stderr=subprocess.PIPE)

    return SimpleNamespace(run=run, source=source, target=destination / 'copy', calls=calls)


def test_snapshot_runs_real_bounded_helper_and_verifies_files(helper, monkeypatch):
    monkeypatch.setattr(tl, 'CHUNK', 7)
    (helper.source / 'nested').mkdir()
    (helper.source / 'nested/image').write_bytes(b'image fixture ' * 5)
    records = tl.snapshot_tree(helper.run, '/data/images', helper.target)
    assert (helper.target / 'nested/image').read_bytes() == b'image fixture ' * 5
    assert (helper.target / 'nested/image').stat().st_mode & 0o777 == (helper.source / 'nested/image').stat().st_mode & 0o777
    assert len(helper.calls) > 3
    inventory = json.loads(helper.target.with_name('copy-inventory.json').read_bytes())
    assert inventory == records
    assert inventory[-1]['sha256'] == hashlib.sha256(b'image fixture ' * 5).hexdigest()


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'fifo'])
def test_snapshot_rejects_links_and_special_files_before_creating_copy(helper, kind):
    (helper.source / 'original').write_bytes(b'fixture')
    if kind == 'symlink':
        (helper.source / 'bad').symlink_to('original')
    elif kind == 'hardlink':
        os.link(helper.source / 'original', helper.source / 'bad')
    else:
        os.mkfifo(helper.source / 'bad')
    with pytest.raises(subprocess.CalledProcessError):
        tl.snapshot_tree(helper.run, '/data/images', helper.target)
    assert not helper.target.exists()


def test_snapshot_detects_stopped_writer_violation(helper):
    source = helper.source / 'image'
    source.write_bytes(b'original')
    reads = 0

    def run(argv, **kwargs):
        nonlocal reads
        result = helper.run(argv, **kwargs)
        if argv[4] == tl._READ:
            reads += 1
            source.write_bytes(b'mutated!')
        return result

    with pytest.raises(InstallError, match='changed during'):
        tl.snapshot_tree(run, '/data/images', helper.target)
    assert reads == 1
    assert helper.target.stat().st_mode & 0o777 == 0o700


def test_snapshot_rejects_excessive_space_and_existing_destination(helper):
    (helper.source / 'image').write_bytes(b'123456')
    with pytest.raises(InstallError, match='bounded'):
        tl.snapshot_tree(helper.run, '/data/images', helper.target, max_bytes=5)
    helper.target.mkdir()
    with pytest.raises(InstallError, match='new PVC'):
        tl.snapshot_tree(helper.run, '/data/images', helper.target)


def test_credential_snapshot_cannot_persist_on_disk(helper, monkeypatch):
    monkeypatch.setattr(tl.subprocess, 'check_output', lambda *a, **kw: b'ext2/ext3\n')
    with pytest.raises(InstallError, match='memory-backed'):
        tl.snapshot_tree(helper.run, '/data/config', helper.target)
    assert not helper.calls


@pytest.mark.parametrize('name', ['../escape', '/outside', 'a/../outside', 'a\nfile'])
def test_compare_write_confines_member_names(name):
    with pytest.raises(InstallError):
        tl.compare_write(lambda *a, **kw: pytest.fail('transport called'),
                         '/data/config', name, None, b'credential')


def test_compare_write_supplies_exact_cas_and_bounds():
    def run(argv, *, input, capture):
        assert argv[5:] == ['/data/config', 'tls/cert.pem']
        header, content = input.split(b'\n', 1)
        record = json.loads(header)
        assert record['before'] == 'a' * 64
        assert record['size'] == len(content)
        assert record['after'] == hashlib.sha256(content).hexdigest()
        return record['after'].encode()

    assert tl.compare_write(run, '/data/config', 'tls/cert.pem', 'a' * 64,
                            b'public cert', mode=0o644) == hashlib.sha256(b'public cert').hexdigest()
    with pytest.raises(InstallError, match='custody'):
        tl.compare_write(run, '/data/config', 'tls/cert.pem', None, b'public', mode=0o777)


@pytest.mark.skipif(os.geteuid() != 0, reason='real remote owner-preserving credential write needs root')
def test_real_compare_write_replay_and_foreign_write_refusal(helper):
    path = helper.source / 'candidate'
    path.write_bytes(b'old')
    before = hashlib.sha256(b'old').hexdigest()
    for _ in range(2):
        assert tl.compare_write(helper.run, '/data/images', 'candidate', before,
                                b'approved', uid=0, gid=0) == hashlib.sha256(b'approved').hexdigest()
        assert path.read_bytes() == b'approved'
    path.write_bytes(b'foreign')
    with pytest.raises(subprocess.CalledProcessError):
        tl.compare_write(helper.run, '/data/images', 'candidate', before, b'approved', uid=0, gid=0)
    assert path.read_bytes() == b'foreign'


def test_remote_consumer_proof_is_still_strictly_validated():
    for proof in ({}, {'management_https': 'verified', 'certificate_sha256': 'not-a-hash'}):
        with pytest.raises(InstallError, match='proof'):
            cm._consumer_proof(SimpleNamespace(lifecycle_consumer_proof=lambda: proof))
    expected = {'management_https': 'verified', 'certificate_sha256': 'a' * 64}
    assert cm._consumer_proof(SimpleNamespace(lifecycle_consumer_proof=lambda: expected)) == expected


def test_topology_hooks_preserve_transport_and_stopped_writer_checks():
    calls = []
    adapter = SimpleNamespace(
        pin_runtime=lambda: calls.append('pin'),
        stop_writers=lambda c, **kw: calls.append(('stop', c, kw)),
        assert_writers_stopped=lambda: calls.append('assert'),
        before_console_start=lambda: calls.append('sync'),
        capture_plan=lambda: ('sources', 'volumes', 'writers'),
        maintenance_run=lambda argv, **kw: (argv, kw))
    cm._pin_runtime(adapter)
    cm._stop(adapter, ['owned'], recovering_clean_operation=True)
    trust._stopped(adapter)
    cm._before_console_start(adapter)
    assert backup.capture_plan(adapter) == ('sources', 'volumes', 'writers')
    assert calls == ['pin', ('stop', ['owned'], {'recovering_clean_operation': True}), 'assert', 'sync']
    argv, kwargs = trust._one_shot(adapter, 'print(1)', 'argument')
    assert argv[-1] == 'argument'
    assert kwargs == {'capture': True}


def test_backup_targets_do_not_confuse_layouts():
    for target, expected in [('docker', 'single-docker'), ('split-docker', 'split-docker'),
                             ('docker-split', 'split-docker'),
                             ('kubernetes', 'kubernetes')]:
        assert backup.target_name(SimpleNamespace(config={'target': target})) == expected


@pytest.mark.parametrize('bad_proof', [False, True])
def test_kubernetes_seeder_uses_isolated_helper_and_always_stops(tmp_path, monkeypatch, bad_proof):
    config = tmp_path / 'config'
    config.mkdir()
    (config / 'secrets.json.age').write_bytes(b'encrypted fixture')
    plain = json.dumps({'seeder': {'announce_token': {'value': 'test-only'}}}).encode()
    monkeypatch.setattr(cm, '_decrypt', lambda *args: plain)
    events = []
    hashes = ['a' * 40, 'b' * 40]
    tx = SimpleNamespace(id='approved-operation', identity=tmp_path / 'independent',
                         sources={'volume-iris-config': config}, record={},
                         save=lambda phase: events.append(('save', phase)))

    def run(argv, **kwargs):
        if argv[4] == kube_credentials._CANONICAL_HASHES:
            return json.dumps(hashes).encode()
        assert argv[4] == cm._SEEDER_SCRIPT
        assert argv[-2] == tx.id
        assert tx.record['original_info_hashes'] == hashes
        events.append('rotate')
        return json.dumps({'credential_changed': True, 'isolated_tracker_proof': True,
                           'info_hashes': [] if bad_proof else hashes}).encode()

    install = SimpleNamespace(base=tmp_path, assert_writers_stopped=lambda: events.append('stopped'),
                              maintenance_run=run,
                              seeder_maintenance_start=lambda op: events.append(('start', op)),
                              seeder_maintenance_stop=lambda op: events.append(('stop', op)))
    if bad_proof:
        with pytest.raises(InstallError, match='serving proof'):
            kube_credentials.apply_seeder(install, tx)
        assert 'seeder_proof' not in tx.record
    else:
        kube_credentials.apply_seeder(install, tx)
        assert tx.record['seeder_proof']['info_hashes'] == hashes
    assert events[0] == 'stopped'
    assert events.index(('save', 'applying')) < events.index(('start', tx.id))
    assert events[-1] == ('stop', tx.id)


def test_kubernetes_seeder_recovery_reuses_exact_prior_canonical_hashes(tmp_path):
    hashes = ['a' * 40]
    tx = SimpleNamespace(id='same-approved-operation', record={
        'original_seeder_fingerprint': 'f' * 64, 'original_info_hashes': hashes},
        save=lambda phase: None)
    events = []

    def run(argv, **kwargs):
        assert argv[4] == cm._SEEDER_SCRIPT
        assert argv[-1] == 'f' * 64
        return json.dumps({'credential_changed': True, 'isolated_tracker_proof': True,
                           'info_hashes': hashes}).encode()

    install = SimpleNamespace(assert_writers_stopped=lambda: None, maintenance_run=run,
                              seeder_maintenance_start=lambda op: events.append(op),
                              seeder_maintenance_stop=lambda op: events.append(op))
    kube_credentials.apply_seeder(install, tx)
    assert events == [tx.id, tx.id]


@pytest.mark.parametrize('remote_refuses', [False, True])
def test_remote_cas_precedes_local_write_and_finalize_precedes_checkpoint(tmp_path, monkeypatch, remote_refuses):
    path = tmp_path / 'credential'
    path.write_bytes(b'old')
    candidate = tmp_path / 'candidate-0.age'
    candidate.write_bytes(b'encrypted new')
    before, after = (hashlib.sha256(value).hexdigest() for value in (b'old', b'new'))
    plan = [{'path': str(path), 'candidate': candidate.name, 'before': before, 'after': after,
             'mode': 0o600, 'uid': os.geteuid(), 'gid': os.getegid()}]
    (tmp_path / 'write-plan.json').write_text(json.dumps(plan))
    compose = tmp_path / 'compose.json'
    compose.write_text('{}')
    events = []
    install = SimpleNamespace(compose_file=compose,
        journal=SimpleNamespace(document={'completed': {}}, save=lambda: events.append('checkpoint')))

    def publish(target, expected, value, mode, uid, gid):
        assert target.read_bytes() == b'old'
        assert expected == before and value == b'new'
        events.append('remote-cas')
        if remote_refuses:
            raise InstallError('remote drift')

    def finalize(transaction):
        assert path.read_bytes() == b'new'
        assert not install.journal.document['completed']
        events.append('finalize')

    install.publish_credential_file = publish
    install.finalize_credential_configuration = finalize
    tx = object.__new__(cm.Transaction)
    tx.directory = tx.base = tmp_path
    tx.install, tx.sources, tx.record, tx.kind, tx.identity = install, {}, {}, 'management-tls', tmp_path / 'identity'
    monkeypatch.setattr(cm, '_decrypt', lambda *args: b'new')
    monkeypatch.setattr(cm.os, 'chown', lambda *args: None)
    if remote_refuses:
        with pytest.raises(InstallError, match='remote drift'):
            tx.apply_plan()
        assert path.read_bytes() == b'old'
        assert events == ['remote-cas']
    else:
        tx.apply_plan()
        assert events == ['remote-cas', 'finalize', 'checkpoint']


@pytest.mark.parametrize('cipher_changes', [False, True])
def test_live_ciphertext_reader_checks_actual_files_and_ignores_audit_writes(helper, cipher_changes):
    (helper.source / 'secrets.json.age').write_bytes(b'current encrypted state')
    (helper.source / 'audit.jsonl').write_bytes(b'initial audit')

    def run(argv, **kwargs):
        assert argv[5] == '/data/config'
        command = list(argv)
        command[5] = '/data/images'
        result = helper.run(command, **kwargs)
        if argv[4] == tl._READ:
            if cipher_changes:
                (helper.source / 'secrets.json.age').write_bytes(b'different encrypted state')
            else:
                (helper.source / 'audit.jsonl').write_bytes(b'new unrelated audit event')
        return result

    if cipher_changes:
        with pytest.raises(InstallError, match='changed during consumer'):
            tl.read_ciphertexts(run)
    else:
        assert tl.read_ciphertexts(run) == {'secrets.json.age': b'current encrypted state'}


@pytest.mark.parametrize('independent_can_read', [False, True])
def test_kubernetes_age_proof_decrypts_live_ciphertexts_not_local_snapshot(tmp_path, monkeypatch, independent_can_read):
    live = {name: b'live post-restart ciphertext ' + name.encode()
            for name in ('secrets.json.age', 'rpc-secret.age', 'tls/key.pem.age')}
    monkeypatch.setattr(tl, 'read_ciphertexts', lambda run: live)
    checked = []
    independent = tmp_path / 'independent'

    def decrypt(install, value, identity):
        assert value in live.values()
        checked.append((value, identity))
        if identity == independent and not independent_can_read:
            return b'unrecoverable'
        return b'actual runtime secret'

    monkeypatch.setattr(cm, '_decrypt', decrypt)
    install = SimpleNamespace(base=tmp_path, run_readonly=lambda *args, **kwargs: None)
    transaction = SimpleNamespace(sources={'volume-iris-config': tmp_path / 'unused-stale-mirror'})
    if independent_can_read:
        assert kube_credentials.verify_live_age(install, transaction, independent) == 3
        assert len(checked) == 6
    else:
        with pytest.raises(InstallError, match='not independently recoverable'):
            kube_credentials.verify_live_age(install, transaction, independent)
