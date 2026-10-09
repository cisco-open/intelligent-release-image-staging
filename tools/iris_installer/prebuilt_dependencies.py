# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Durably accepted local dependency plans and bounded completed-apply recovery.

An interrupted operation can retry its unchanged original host state, or prove
the exact completed package effect. Partial apt transactions and unrelated host
changes require operator inspection; they never authorize a replacement plan.
"""

import hashlib
import io
import json
from pathlib import Path
import re

from . import offline_dependencies as dependencies, offline_inputs, release_kit, ubuntu
from .state import InstallError, regular_bytes


STATUS = Path('/var/lib/dpkg/status')
SCHEMA = 'iris-prebuilt-dependencies-v1'
FIELD = 'dependency_provisioning'


def _sha(value):
    return isinstance(value, str) and bool(re.fullmatch(r'[a-f0-9]{64}', value))


def _plan(plan):
    fields = {'schema', 'closure_sha256', 'status_sha256', 'provider', 'docker_path', 'roots', 'packages'}
    if isinstance(plan, dict) and 'required_roots' in plan:
        fields.add('required_roots')
        roots = plan['required_roots']
        if (not isinstance(roots, list) or not roots
                or any(not isinstance(name, str) or name not in dependencies.ROOT_PACKAGES for name in roots)
                or roots != sorted(set(roots))):
            raise InstallError('Recorded dependency root subset is invalid')
    if (not isinstance(plan, dict) or set(plan) != fields
            or plan['schema'] != 'iris-offline-dependency-plan-v1'
            or not _sha(plan['closure_sha256']) or not _sha(plan['status_sha256'])
            or not isinstance(plan['provider'], list)
            or any(not isinstance(name, str) or name not in dependencies.ENGINE_PACKAGES for name in plan['provider'])
            or plan['provider'] != sorted(set(plan['provider']))
            or (plan['docker_path'] is not None and (not isinstance(plan['docker_path'], str)
                or not Path(plan['docker_path']).is_absolute()))
            or not isinstance(plan['roots'], list) or any(not isinstance(value, str) for value in plan['roots'])
            or not isinstance(plan['packages'], list)):
        raise InstallError('Recorded dependency plan is invalid; preserve the journal')
    names = []
    for package in plan['packages']:
        if (not isinstance(package, dict) or set(package) != {'name', 'version', 'old_version', 'architecture'}
                or not isinstance(package['name'], str)
                or not re.fullmatch(r'[a-z0-9][a-z0-9+.-]*', package['name'])
                or not isinstance(package['version'], str) or not package['version']
                or (package['old_version'] is not None and not isinstance(package['old_version'], str))
                or package['architecture'] not in ('amd64', 'all')):
            raise InstallError('Recorded dependency package plan is invalid; preserve the journal')
        names.append(package['name'])
    if names != sorted(set(names)):
        raise InstallError('Recorded dependency package plan is duplicated or unordered')
    return set(names)


def _status(plan):
    changed = _plan(plan)
    raw = regular_bytes(STATUS, 64 * 1024 ** 2)
    try:
        records = list(dependencies._paragraphs(io.StringIO(raw.decode('utf-8'))))
    except (ValueError, UnicodeError):
        raise InstallError('Host package state is unreadable; the accepted dependency plan is retained') from None
    names = [record.get('Package') for record in records]
    if (any(not isinstance(name, str) for name in names) or len(names) != len(set(names))
            or any(not re.fullmatch(r'(?:install|hold|deinstall|purge|unknown) ok (?:installed|not-installed|config-files)',
                                   record.get('Status', '')) for record in records)):
        raise InstallError('Host has a partial or invalid package transaction; inspect apt/dpkg state; the accepted dependency plan is retained')
    unrelated = {record['Package']: record for record in records if record['Package'] not in changed}
    canonical = json.dumps(unrelated, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(raw).hexdigest(), hashlib.sha256(canonical).hexdigest(), {row['Package']: row for row in records}


def evidence_for_plan(plan):
    """Bind all non-plan dpkg records while the accepted pre-state still holds."""
    status, unrelated, _ = _status(plan)
    if status != plan['status_sha256']:
        raise InstallError('Host package state changed during acceptance; no dependency plan was applied')
    return {'unchanged_records_sha256': unrelated}


def _validate_evidence(closure, plan, evidence):
    _plan(plan)
    if (not isinstance(evidence, dict) or set(evidence) != {'unchanged_records_sha256'}
            or not _sha(evidence['unchanged_records_sha256']) or closure.digest != plan['closure_sha256']):
        raise InstallError('Recorded dependency evidence differs from the authenticated closure')
    dependencies._check_solution(plan['packages'], closure.packages)


def validate_completed_plan(closure, plan, evidence):
    """Validate current readiness without reapplying or forbidding later updates."""
    _validate_evidence(closure, plan, evidence)
    remaining = dependencies.plan_dependencies(closure, status=STATUS, required_roots=plan.get('required_roots'))
    if remaining['packages']:
        raise InstallError('Previously completed dependencies are missing; no replacement plan was adopted or applied')
    return {'status_sha256': remaining['status_sha256']}


def recover_or_validate_complete(closure, plan, evidence):
    """Prove the full accepted effect, never repair a partial transaction."""
    _validate_evidence(closure, plan, evidence)
    status, unrelated, records = _status(plan)
    if unrelated != evidence['unchanged_records_sha256']:
        raise InstallError('Unrelated host package state changed; inspect the host; the accepted dependency plan is retained')
    for package in plan['packages']:
        current = records.get(package['name'], {})
        if (current.get('Status') != 'install ok installed' or current.get('Version') != package['version']
                or current.get('Architecture') != package['architecture']):
            raise InstallError('Accepted dependency application is incomplete or changed; inspect apt/dpkg state; the accepted plan is retained')
    remaining = dependencies.plan_dependencies(closure, status=STATUS, required_roots=plan.get('required_roots'))
    if remaining['packages'] or remaining['status_sha256'] != status:
        raise InstallError('Host does not satisfy the accepted dependency effect; no replacement plan was adopted')
    if plan['docker_path'] is not None and remaining['docker_path'] != plan['docker_path']:
        raise InstallError('Existing Docker executable changed; the accepted dependency plan is retained')
    return {'status_sha256': status}


def apply_accepted_plan(closure, plan, evidence, *, accept_changes=False):
    """Retry only unchanged pre-state, otherwise prove completed effect read-only."""
    if not accept_changes:
        raise InstallError('Offline dependency application requires explicit acceptance')
    # Validate evidence even on the initial apply path, before allowing mutation.
    _validate_evidence(closure, plan, evidence)
    status, unrelated, _ = _status(plan)
    if status == plan['status_sha256']:
        if unrelated != evidence['unchanged_records_sha256']:
            raise InstallError('Recorded dependency baseline is invalid; no package changes were made')
        dependencies.apply_dependencies(closure, plan, accept_changes=True)
    return recover_or_validate_complete(closure, plan, evidence)


def _host_ready(journal, runner):
    target = journal.document['config']['target']
    client = journal.document.get('prebuilt_kubectl')
    if target == 'kubernetes' and client is not None:
        if runner is None:
            raise InstallError('Offline Kubernetes client provisioning requires the installation runner')
        ubuntu.provision_kubernetes_client(runner, local_source=client)
    return ubuntu.preflight_prebuilt(target)


def _check_client_input(journal):
    if 'prebuilt_kubectl' not in journal.document:
        return
    client = journal.document['prebuilt_kubectl']
    if (journal.document['config']['target'] != 'kubernetes' or not isinstance(client, str)
            or not Path(client).is_absolute()):
        raise InstallError('Recorded local Kubernetes client selection is invalid')
    if not any(ubuntu.shutil.which(name, path=ubuntu.SYSTEM_PATH) for name in ('kubectl', 'k3s')):
        ubuntu.validate_kubernetes_input(client)


def provision(journal, kit, *, accept_changes=False, runner=None):
    """Dispatch authenticated profile; keep accepted and completed evidence durable."""
    if not isinstance(kit, release_kit.VerifiedKit):
        raise InstallError('Dependency provisioning requires an authenticated release kit')
    release_kit.assert_resume_selection(journal.document['input_selection'],
        release_kit.selection('prebuilt', kit=kit, offline=kit.offline))
    _check_client_input(journal)
    if kit.profile == 'prepared-host':
        if FIELD in journal.document or 'dependency_changes_accepted' in journal.document:
            raise InstallError('Prepared-host profile contains conflicting dependency authority')
        return _host_ready(journal, runner)
    if kit.profile != 'ubuntu-dependencies':
        raise InstallError('Authenticated dependency profile is unsupported')
    missing = FIELD not in journal.document
    saved = journal.document.get(FIELD)
    if missing and not (accept_changes or journal.document.get('dependency_changes_accepted') is True):
        raise InstallError('Offline dependency provisioning has no recorded explicit acceptance')
    if missing:
        # Initial acceptance is not permanent authority to reconstruct a lost
        # receipt after deployment. Standalone callers use the explicit APIs.
        if journal.document.get('state') != 'INITIALIZING' or journal.document.get('completed') != {}:
            raise InstallError('Recorded dependency plan is missing after initialization; no new plan was authorized')
        from .deploy import _initialization_inputs
        _initialization_inputs(journal)
    with offline_inputs.prepare_dependencies(kit) as closure:
        if missing:
            plan = dependencies.plan_dependencies(closure, status=STATUS)
            saved = {'schema': SCHEMA, 'kit': kit.receipt(), 'accepted_changes': True,
                     'plan': plan, 'evidence': evidence_for_plan(plan), 'phase': 'accepted'}
            journal.document[FIELD] = saved
            journal.save()
        fields = {'schema', 'kit', 'accepted_changes', 'plan', 'evidence', 'phase'}
        if isinstance(saved, dict) and saved.get('phase') == 'complete':
            fields.add('result')
        if (not isinstance(saved, dict) or set(saved) != fields or saved['schema'] != SCHEMA
                or saved['kit'] != kit.receipt() or saved['accepted_changes'] is not True
                or saved['phase'] not in ('accepted', 'complete')):
            raise InstallError('Recorded dependency acceptance changed; preserve the original journal')
        if saved['phase'] == 'complete':
            if (not isinstance(saved['result'], dict) or set(saved['result']) != {'status_sha256'}
                    or not _sha(saved['result']['status_sha256'])):
                raise InstallError('Recorded dependency completion is invalid')
            validate_completed_plan(closure, saved['plan'], saved['evidence'])
        else:
            result = apply_accepted_plan(closure, saved['plan'], saved['evidence'], accept_changes=True)
            saved = dict(saved, phase='complete', result=result)
            journal.document[FIELD] = saved
            journal.save()
    return _host_ready(journal, runner)
