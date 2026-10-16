# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Durable local acceptance and interrupted effect proofs; no host apt apply."""

from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import prebuilt_dependencies as subject, deploy, guest_inputs, prebuilt_install, release_kit
from iris_installer.state import InstallError, Journal
from test_installer_offline_dependencies import signed_repository


def record(name, version='1', *, status='install ok installed', architecture='amd64'):
    return f'Package: {name}\nStatus: {status}\nArchitecture: {architecture}\nVersion: {version}\nDescription: fixture\n\n'


@pytest.fixture
def host(tmp_path, monkeypatch):
    status = tmp_path / 'status'
    baseline = record('owner-package')
    status.write_text(baseline)
    monkeypatch.setattr(subject, 'STATUS', status)
    package = {'name': 'age', 'version': '2', 'old_version': None, 'architecture': 'amd64'}
    closure = SimpleNamespace(digest='a' * 64, packages={'age': package})
    plan = {'schema': 'iris-offline-dependency-plan-v1', 'closure_sha256': closure.digest,
            'status_sha256': hashlib.sha256(status.read_bytes()).hexdigest(), 'provider': [],
            'docker_path': None, 'roots': ['age=2'], 'packages': [package]}
    calls = []
    def planning(value, *, status, required_roots=None):
        assert value is closure and status == subject.STATUS
        assert required_roots == plan.get('required_roots')
        calls.append('plan')
        result = deepcopy(plan)
        result['status_sha256'] = hashlib.sha256(status.read_bytes()).hexdigest()
        if 'Package: age\n' in status.read_text():
            result['packages'], result['roots'] = [], []
        return result
    def apply(value, accepted, *, accept_changes):
        assert value is closure and accepted == plan and accept_changes is True
        calls.append('apply')
        if accepted['packages']:
            status.write_text(baseline + record('age', '2'))
    monkeypatch.setattr(subject.dependencies, 'plan_dependencies', planning)
    monkeypatch.setattr(subject.dependencies, 'apply_dependencies', apply)
    return SimpleNamespace(status=status, baseline=baseline, closure=closure, plan=plan, calls=calls)


@pytest.fixture
def install(tmp_path, monkeypatch, host):
    kit = release_kit.VerifiedKit(tmp_path, 'v2026.10.09', 'b' * 40, 'c' * 64,
                                  'd' * 64, 'e' * 64, 'f' * 64, True, (), 'ubuntu-dependencies')
    directory = tmp_path / 'installation'
    directory.mkdir(mode=0o700)
    journal = Journal(directory)
    journal.document = {'schema': 1, 'id': 'fixture', 'config': {'target': 'docker'},
                        'input_selection': release_kit.selection('prebuilt', kit=kit, offline=True),
                        'state': 'INITIALIZING', 'completed': {}, 'dependency_changes_accepted': True}
    roots = {'a.pub': 'ssh-ed25519 AAAA fixture\n', 'b.pub': 'ssh-ed25519 BBBB fixture\n'}
    journal.document.update(initialization={'source': str(tmp_path / 'source'), 'public_roots': roots},
        source_manifest={'code': '1' * 64},
        root_digests={name: hashlib.sha256(value.encode()).hexdigest() for name, value in roots.items()})
    journal.save()
    @contextmanager
    def prepare(value):
        assert value is kit
        host.calls.append('validate-closure')
        yield host.closure
    monkeypatch.setattr(subject.offline_inputs, 'prepare_dependencies', prepare)
    monkeypatch.setattr(subject.ubuntu, 'preflight_prebuilt', lambda target: host.calls.append('host-ready'))
    return SimpleNamespace(journal=journal, kit=kit, host=host)


def test_plan_and_original_initialization_are_durable_before_apply(install, monkeypatch):
    original = subject.dependencies.apply_dependencies
    def apply(*args, **kwargs):
        saved = json.loads(install.journal.path.read_bytes())
        assert saved['completed'] == {} and saved['state'] == 'INITIALIZING'
        accepted = saved[subject.FIELD]
        assert accepted['phase'] == 'accepted' and accepted['accepted_changes'] is True
        assert accepted['plan'] == install.host.plan and accepted['kit'] == install.kit.receipt()
        assert accepted['evidence'] == subject.evidence_for_plan(install.host.plan)
        original(*args, **kwargs)
    monkeypatch.setattr(subject.dependencies, 'apply_dependencies', apply)
    subject.provision(install.journal, install.kit)
    saved = json.loads(install.journal.path.read_bytes())[subject.FIELD]
    assert saved['phase'] == 'complete' and saved['result']['status_sha256'] != saved['plan']['status_sha256']
    assert install.host.calls == ['validate-closure', 'plan', 'apply', 'plan', 'host-ready']


def test_absent_explicit_authority_never_plans_or_applies(install):
    install.journal.document.pop('dependency_changes_accepted')
    with pytest.raises(InstallError, match='explicit acceptance'):
        subject.provision(install.journal, install.kit)
    assert install.host.calls == []


def test_explicit_null_receipt_never_authorizes_a_fresh_plan(install):
    install.journal.document[subject.FIELD] = None
    with pytest.raises(InstallError, match='acceptance changed'):
        subject.provision(install.journal, install.kit)
    assert install.host.calls == ['validate-closure']


@pytest.mark.parametrize('changed', ['initialized', 'completed-stage', 'missing-reservation', 'changed-roots'])
def test_missing_receipt_cannot_reconstruct_authority_outside_original_reservation(install, changed):
    document = install.journal.document
    if changed == 'initialized':
        document['state'] = 'INITIALIZED'
        document.pop('initialization')
    elif changed == 'completed-stage':
        document['completed']['images'] = {'image': 'identity'}
    elif changed == 'missing-reservation':
        document.pop('initialization')
    else:
        document['initialization']['public_roots']['a.pub'] = 'ssh-ed25519 CHANGED fixture\n'
    with pytest.raises(InstallError, match='missing|changed'):
        subject.provision(install.journal, install.kit)
    assert install.host.calls == []


def test_explicit_null_client_is_not_treated_as_an_absent_option(install):
    install.journal.document['config']['target'] = 'kubernetes'
    install.journal.document['prebuilt_kubectl'] = None
    with pytest.raises(InstallError, match='selection is invalid'):
        subject.provision(install.journal, install.kit)
    assert install.host.calls == []


def test_completed_effect_preserves_accepted_root_subset(host):
    host.plan['required_roots'] = ['age']
    evidence = subject.evidence_for_plan(host.plan)
    subject.apply_accepted_plan(host.closure, host.plan, evidence, accept_changes=True)
    assert host.calls == ['apply', 'plan']


def test_exact_completed_effect_uses_real_signed_repository_and_local_resolver(signed_repository, tmp_path, monkeypatch):
    directory, keyring, digest = signed_repository
    status = tmp_path / 'isolated-status'
    status.write_text('')
    monkeypatch.setattr(subject, 'STATUS', status)
    monkeypatch.setattr(subject.dependencies.shutil, 'which', lambda *a, **kw: None)
    monkeypatch.setattr(subject.dependencies, 'apply_dependencies', lambda *a, **kw: pytest.fail('Read-only proof'))
    with subject.dependencies.validate_closure(directory, digest, keyring=keyring) as closure:
        plan = subject.dependencies.plan_dependencies(closure, status=status, required_roots=['age'])
        evidence = subject.evidence_for_plan(plan)
        status.write_text(record('age', '1.0'))
        result = subject.recover_or_validate_complete(closure, plan, evidence)
        assert result == {'status_sha256': hashlib.sha256(status.read_bytes()).hexdigest()}
        status.write_text(record('age', '2.0') + record('owner-package'))
        subject.validate_completed_plan(closure, plan, evidence)
        with pytest.raises(InstallError, match='Unrelated'):
            subject.recover_or_validate_complete(closure, plan, evidence)


def test_acceptance_save_failure_stops_before_apply(install, monkeypatch):
    monkeypatch.setattr(install.journal, 'save', lambda: (_ for _ in ()).throw(OSError('disk failure')))
    with pytest.raises(OSError, match='disk failure'):
        subject.provision(install.journal, install.kit)
    assert 'apply' not in install.host.calls and install.host.status.read_text() == install.host.baseline


@pytest.mark.parametrize('completed_apply', [False, True])
def test_interrupted_apply_retries_only_original_state_or_proves_exact_completion(install, monkeypatch, completed_apply):
    original = subject.dependencies.apply_dependencies
    def interrupted(*args, **kwargs):
        if completed_apply:
            original(*args, **kwargs)
        raise InstallError('interrupted apt')
    monkeypatch.setattr(subject.dependencies, 'apply_dependencies', interrupted)
    with pytest.raises(InstallError, match='interrupted apt'):
        subject.provision(install.journal, install.kit)
    install.journal.document = json.loads(install.journal.path.read_bytes())
    assert install.journal.document[subject.FIELD]['phase'] == 'accepted'
    monkeypatch.setattr(subject.dependencies, 'apply_dependencies', original)
    install.host.calls.clear()
    subject.provision(install.journal, install.kit)
    assert install.host.calls.count('apply') == (0 if completed_apply else 1)
    assert install.journal.document[subject.FIELD]['phase'] == 'complete'


def test_crash_before_completion_checkpoint_recovers_without_reapply(install, monkeypatch):
    save = install.journal.save
    def interrupted():
        if install.journal.document.get(subject.FIELD, {}).get('phase') == 'complete':
            raise OSError('checkpoint interrupted')
        save()
    monkeypatch.setattr(install.journal, 'save', interrupted)
    with pytest.raises(OSError, match='checkpoint interrupted'):
        subject.provision(install.journal, install.kit)
    install.journal.document = json.loads(install.journal.path.read_bytes())
    monkeypatch.setattr(install.journal, 'save', save)
    install.host.calls.clear()
    subject.provision(install.journal, install.kit)
    assert 'apply' not in install.host.calls


@pytest.mark.parametrize('change', ['partial', 'reinstreq', 'missing', 'wrong-version', 'held', 'architecture',
                                  'extra', 'removed-owner', 'changed-owner', 'owner-hold'])
def test_changed_or_partial_host_state_never_authorizes_replanning(host, change):
    evidence = subject.evidence_for_plan(host.plan)
    raw = host.baseline + record('age', '2')
    if change == 'partial': raw = host.baseline + record('age', '2', status='install ok unpacked')
    elif change == 'reinstreq': raw = host.baseline + record('age', '2', status='install reinstreq installed')
    elif change == 'missing': raw = host.baseline + '\n'
    elif change == 'wrong-version': raw = host.baseline + record('age', '3')
    elif change == 'held': raw = host.baseline + record('age', '2', status='hold ok installed')
    elif change == 'architecture': raw = host.baseline + record('age', '2', architecture='arm64')
    elif change == 'extra': raw += record('unapproved')
    elif change == 'removed-owner': raw = record('age', '2')
    elif change == 'changed-owner': raw = record('owner-package', '2') + record('age', '2')
    else: raw = record('owner-package', status='hold ok installed') + record('age', '2')
    host.status.write_text(raw)
    with pytest.raises(InstallError, match='retained|replacement plan'):
        subject.apply_accepted_plan(host.closure, host.plan, evidence, accept_changes=True)
    assert host.calls == []


def test_completed_receipt_still_validates_actual_dependencies(install):
    subject.provision(install.journal, install.kit)
    install.host.calls.clear()
    subject.provision(install.journal, install.kit)
    assert 'apply' not in install.host.calls
    install.host.status.write_text(install.host.baseline)
    with pytest.raises(InstallError, match='missing'):
        subject.provision(install.journal, install.kit)
    assert 'apply' not in install.host.calls


@pytest.mark.parametrize('field,value', [('kit', {}), ('phase', 'other'), ('accepted_changes', False),
                                      ('plan', {}), ('evidence', {}), ('result', {})])
def test_malformed_journal_never_adopts_replacement_authority(install, field, value):
    subject.provision(install.journal, install.kit)
    install.host.calls.clear()
    install.journal.document[subject.FIELD][field] = value
    with pytest.raises(InstallError):
        subject.provision(install.journal, install.kit)
    assert 'apply' not in install.host.calls and 'host-ready' not in install.host.calls


def test_completed_receipt_allows_later_unrelated_and_dependency_security_updates(install):
    subject.provision(install.journal, install.kit)
    saved = deepcopy(install.journal.document[subject.FIELD])
    install.host.status.write_text(record('owner-package', '2') + record('age', '3') + record('another-owner-package'))
    install.host.calls.clear()
    subject.provision(install.journal, install.kit)
    assert 'apply' not in install.host.calls and 'host-ready' in install.host.calls
    assert install.journal.document[subject.FIELD] == saved


def test_empty_plan_records_and_verifies_noop_without_host_mutation(install):
    install.host.plan['packages'], install.host.plan['roots'] = [], []
    subject.provision(install.journal, install.kit)
    assert install.journal.document[subject.FIELD]['phase'] == 'complete'


def test_prepared_profile_stays_read_only_and_preserves_optional_client(tmp_path, monkeypatch):
    kit = release_kit.VerifiedKit(tmp_path, 'v2026.10.09', 'b' * 40, 'c' * 64,
                                  'd' * 64, 'e' * 64, 'f' * 64, True, ())
    journal = SimpleNamespace(document={'config': {'target': 'kubernetes'},
        'input_selection': release_kit.selection('prebuilt', kit=kit, offline=True),
        'prebuilt_kubectl': '/selected/kubectl'})
    events, runner = [], object()
    monkeypatch.setattr(subject.ubuntu, 'provision_kubernetes_client',
        lambda supplied, **kw: events.append(('client', supplied, kw)))
    monkeypatch.setattr(subject.ubuntu, 'validate_kubernetes_input', lambda path: None)
    monkeypatch.setattr(subject.ubuntu, 'preflight_prebuilt', lambda target: events.append(('ready', target)))
    monkeypatch.setattr(subject.offline_inputs, 'prepare_dependencies', lambda *a: pytest.fail('No apt'))
    subject.provision(journal, kit, runner=runner)
    assert events == [('client', runner, {'local_source': '/selected/kubectl'}), ('ready', 'kubernetes')]


def test_docker_adapter_dispatches_authenticated_profile_without_source_fallback(monkeypatch):
    calls = []
    obj = SimpleNamespace(prebuilt=lambda: True, journal=object(), _verified_kit=object(), command=object())
    monkeypatch.setattr(subject, 'provision', lambda *args, **kwargs: calls.append((args, kwargs)))
    monkeypatch.setattr(deploy.ubuntu, 'provision', lambda *a: pytest.fail('No source fallback'))
    deploy.DockerInstall.provision_host(obj)
    assert calls == [((obj.journal, obj._verified_kit), {'runner': obj.command})]


@pytest.fixture
def startup(tmp_path, monkeypatch):
    source, roots = tmp_path / 'input', tmp_path / 'roots'
    source.mkdir(); roots.mkdir()
    (source / 'code').write_bytes(b'authenticated fixture source')
    manifest = {'code': hashlib.sha256((source / 'code').read_bytes()).hexdigest()}
    (source / 'INSTALLER-SOURCE.json').write_text(json.dumps(manifest))
    for name, value in [('a.pub', 'AAAA'), ('b.pub', 'BBBB')]:
        (roots / name).write_text('ssh-ed25519 ' + value + ' fixture\n')
    args = SimpleNamespace(target='docker', instance='iris-test', host='192.0.2.10',
        console_bind='127.0.0.1', console_port=18080, recovery_recipient='age1' + 'q' * 58,
        peer_tls='required', accept_changes=True, state_dir=tmp_path / 'state',
        source=source, roots_dir=roots, certificate=None)
    kit = release_kit.VerifiedKit(tmp_path, 'v2026.10.09', 'b' * 40, 'c' * 64,
                                  'd' * 64, 'e' * 64, 'f' * 64, True, (), 'ubuntu-dependencies')
    selection = {'input_selection': release_kit.selection('prebuilt', kit=kit, offline=True),
                 'release_kit': {'directory': '/kit', 'verifier': '/gh', 'trusted_root': '/root.json'},
                 'prebuilt_ioxclient': '/licensed/ioxclient'}
    events = []
    # Only the entrypoint's privilege predicate is simulated. Journal/filesystem
    # custody continues to use the real caller, and no subprocess can execute.
    monkeypatch.setattr(deploy, 'os', SimpleNamespace(**dict(vars(os), geteuid=lambda: 0)))
    monkeypatch.setattr(deploy.ubuntu, 'check_platform', lambda: None)
    monkeypatch.setattr(prebuilt_install, 'prepare_selection', lambda *a: events.append('authenticate') or selection)
    monkeypatch.setattr(prebuilt_install, 'verify_selected', lambda *a: events.append('reauthenticate') or kit)
    monkeypatch.setattr(prebuilt_install, 'bind_source', lambda *a: events.append('source'))
    monkeypatch.setattr(guest_inputs, 'verify_guest_inputs', lambda *a: events.append('guest'))
    monkeypatch.setattr(prebuilt_install, 'validate_packaging_tool', lambda *a: events.append('licensed-tool'))
    monkeypatch.setattr(deploy, '_new_host_preflight', lambda *a: events.append('preflight'))
    def provisioning(journal, verified, **kwargs):
        assert verified is kit
        saved = json.loads(journal.path.read_bytes())
        assert saved['state'] == 'INITIALIZING' and saved['completed'] == {}
        assert saved['dependency_changes_accepted'] is True
        assert saved['source_manifest'] == manifest and len(saved['root_digests']) == 2
        events.append('provision')
    monkeypatch.setattr(subject, 'provision', provisioning)
    def initialize(journal):
        events.append('snapshot')
        journal.document.pop('initialization')
        journal.document['state'] = 'INITIALIZED'
        journal.save()
    monkeypatch.setattr(deploy, 'complete_initialization', initialize)
    monkeypatch.setattr(deploy, 'installation', lambda journal: SimpleNamespace(resume=lambda *a: 20))
    monkeypatch.setattr(deploy, 'run', lambda *a, **kw: pytest.fail('No host command'))
    return args, events


def test_new_profile_reserves_original_inputs_before_provision_then_checks_ownership(startup):
    args, events = startup
    assert deploy.start(args) == 20
    assert events == ['authenticate', 'reauthenticate', 'provision', 'preflight', 'snapshot']


@pytest.mark.parametrize('changed', [None, 'source', 'roots'])
def test_interrupted_bootstrap_reauthenticates_and_refuses_reserved_input_drift(startup, monkeypatch, changed):
    args, events = startup
    provision = subject.provision
    monkeypatch.setattr(subject, 'provision', lambda *a, **kw: (_ for _ in ()).throw(InstallError('interrupted bootstrap')))
    with pytest.raises(InstallError, match='interrupted bootstrap'):
        deploy.start(args)
    monkeypatch.setattr(subject, 'provision', provision)
    if changed == 'source':
        (args.source / 'code').write_bytes(b'changed')
    elif changed == 'roots':
        path = args.state_dir / 'installation.json'
        value = json.loads(path.read_bytes())
        value['initialization']['public_roots']['a.pub'] = 'ssh-ed25519 CHANGED fixture\n'
        path.write_text(json.dumps(value))
    events.clear()
    if changed:
        with pytest.raises(InstallError, match='changed'):
            deploy.resume(args)
        assert 'provision' not in events and 'snapshot' not in events
    else:
        assert deploy.resume(args) == 20
        assert events == ['reauthenticate', 'source', 'guest', 'licensed-tool', 'provision', 'preflight', 'snapshot']


def test_declined_changes_never_authenticate_or_reserve_bootstrap(startup):
    args, events = startup
    args.accept_changes = False
    with pytest.raises(InstallError, match='accept-changes'):
        deploy.start(args)
    assert events == [] and not args.state_dir.exists()


def test_initialization_resume_rechecks_licensed_tool_before_package_changes(startup, monkeypatch):
    args, events = startup
    provision = subject.provision
    monkeypatch.setattr(subject, 'provision', lambda *a, **kw: (_ for _ in ()).throw(InstallError('interrupted bootstrap')))
    with pytest.raises(InstallError):
        deploy.start(args)
    monkeypatch.setattr(subject, 'provision', provision)
    monkeypatch.setattr(prebuilt_install, 'validate_packaging_tool',
                        lambda *a: (_ for _ in ()).throw(InstallError('licensed tool changed')))
    events.clear()
    with pytest.raises(InstallError, match='licensed tool changed'):
        deploy.resume(args)
    assert events == ['reauthenticate', 'source', 'guest']


@pytest.mark.parametrize('existing', [None, 'kubectl', 'k3s'])
def test_needed_kubernetes_input_checked_before_any_dependency_plan(install, monkeypatch, existing):
    install.journal.document['config']['target'] = 'kubernetes'
    install.journal.document['prebuilt_kubectl'] = '/missing/kubectl'
    monkeypatch.setattr(subject.ubuntu.shutil, 'which',
                        lambda name, **kw: '/usr/bin/' + name if name == existing else None)
    monkeypatch.setattr(subject.ubuntu, 'validate_kubernetes_input',
                        lambda *a: (_ for _ in ()).throw(InstallError('local client changed')))
    monkeypatch.setattr(subject.ubuntu, 'provision_kubernetes_client', lambda *a, **kw: None)
    if existing is None:
        with pytest.raises(InstallError, match='local client changed'):
            subject.provision(install.journal, install.kit, runner=object())
        assert install.host.calls == []
    else:
        subject.provision(install.journal, install.kit, runner=object())
        assert 'apply' in install.host.calls and 'host-ready' in install.host.calls
