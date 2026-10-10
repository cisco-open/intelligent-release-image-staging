# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Explicit, forward-only application upgrades for source-built single Docker.

The operation preserves the existing installation identity and storage. Once
publication starts, recovery finishes that same approved generation; it never
starts old code over data that newer code may have written.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace
import uuid

from . import backup, deploy, managed_worker, restore, restore_storage as storage
from . import upgrade_candidate as candidate, upgrade_plan as plan, upgrade_runtime as runtime
from .upgrade_state import Operation, guard, read
from .lifecycle_history import Store
from .state import InstallError, Journal, atomic_write, regular_bytes


def _root(base):
    managed_worker._root()
    return managed_worker._path(base)


def _idle(journal, *, operation_id=None):
    restore.guard(journal.directory, instance_id=journal.document['id'], upgrade_operation_id=operation_id)
    runtime.jobs_idle(journal.directory)
    path = journal.directory / 'credential-operation.json'
    if path.exists() or path.is_symlink():
        value = json.loads(regular_bytes(path))
        plan.require(value.get('instance_id') == journal.document['id'] and (
            value.get('phase') == 'rotated' or
            value.get('phase') == 'refused' and value.get('mutations_admitted') is False),
            'Finish or recover credential maintenance before upgrading')


def prepare(args):
    base = _root(args.state_dir)
    plan.require(args.accept_changes, 'Review the release and pass --accept-changes to build an upgrade candidate')
    with managed_worker._service_lock(base):
        worker = runtime.worker_state(base)
        # Independent recovery trust must already be provisioned. Upgrade
        # preparation cannot select its own backup signer as trusted authority.
        restore.custody(base, Path(worker['record']['recovery_identity']))
        with Journal(base).locked() as journal:
            plan.require_source_build(journal.document)
            _idle(journal)
            install = deploy.DockerInstall(journal)
            sources, volumes, containers = backup.capture_plan(install)
            runtime.drain(install)
            plan.require(all(row['running'] for row in containers),
                         'Both existing services must be healthy and running before preparation')
            selection, proof = candidate.selected_source(install, args.source, args.source_proof,
                                                        args.source_proof_sha256, args.source_commit)
            before_history = copy.deepcopy(journal.document)
        # A prior worker may predate retention. Establish its independent
        # replay commitment before approving an immutable upgrade generation,
        # never for an unauthenticated candidate or under a nested Journal lock.
        history = Store(base)
        plan.require(runtime.equal(runtime.worker_state(base), worker),
                     'The managed worker changed during upgrade preparation')
        with Journal(base).locked() as journal:
            expected = dict(before_history, lifecycle_history=history.anchor)
            plan.require(runtime.equal(journal.document, expected),
                         'The deployment changed while preparing maintenance history')
            _idle(journal)
            install = deploy.DockerInstall(journal)
            sources, volumes, containers = backup.capture_plan(install)
            runtime.drain(install)
            plan.require(all(row['running'] for row in containers),
                         'Both existing services must remain running during preparation')
            original = copy.deepcopy(journal.document)
            compose = regular_bytes(install.compose_file).decode('utf-8')
            operation = Operation(base, str(uuid.uuid4()), original['id'])
            operation.create({'original': original, 'worker_before': worker, 'selection': selection})
            atomic_write(operation.directory / 'source-proof.json', proof)
            print('Preparing application upgrade ' + operation.id, flush=True)
            built = candidate.build(install, operation, selection, args.source)
            install.verify_inputs()
            plan.require(runtime.equal(original, journal.document)
                         and regular_bytes(install.compose_file).decode('utf-8') == compose,
                         'The existing deployment changed during candidate preparation')
            resources = {'volumes': volumes, 'containers': containers}
            review = {'schema': plan.SCHEMA, 'operation_id': operation.id, 'instance_id': original['id'],
                'original': original, 'compose_before': compose, 'worker_before': worker,
                'resources': resources, 'candidate': built,
                'preserves': ['accounts', 'keys', 'installation-id', 'storage', 'replay-authority'],
                'device_requirement': 'confirmed-removal-before-upgrade-then-reonboard',
                'scope': 'source-build-single-docker', 'rollback': 'not-supported-forward-recovery-only'}
            operation.record['candidate'] = built
            operation.write_plan(review)
            result = {'operation_id': operation.id, 'plan_sha256': operation.record['plan_sha256'],
                      'phase': 'prepared', 'source_commit': selection['commit'],
                      'plan': str(operation.directory / 'plan.json')}
            print(json.dumps(result, sort_keys=True))
            return 0


def _install(journal, operation):
    install = deploy.DockerInstall(journal)
    install.application_upgrade_id = operation.id
    return install


def _check_original(journal, review):
    plan.require(runtime.equal(journal.document, review['original']),
                 'The current installation differs from the reviewed upgrade preimage')
    plan.require(regular_bytes(journal.directory / 'compose.json').decode('utf-8') == review['compose_before'],
                 'The current Compose file differs from the reviewed upgrade preimage')


def _stopped(install, operation, review):
    containers = review['resources']['containers']
    backup.stop_writers(install, containers, recovering_clean_operation=bool(operation.record.get('clean_stop')))
    # Resolve ownership and ALL writable mounts again after services stop.
    sources, volumes, observed = backup.capture_plan(install)
    plan.require(runtime.equal(volumes, review['resources']['volumes'])
                 and {row['id'] for row in observed} == {row['id'] for row in containers},
                 'The reviewed deployment storage or containers changed')
    runtime.drain(install, stopped=True)
    runtime.jobs_idle(install.base)
    operation.record['clean_stop'] = True
    current_sources = {name: str(sources[name]) for name in ('volume-iris-config', 'volume-iris-state')}
    plan.require('authority_sources' not in operation.record or
                 runtime.equal(operation.record['authority_sources'], current_sources),
                 'Stopped authority storage paths changed')
    operation.record['authority_sources'] = current_sources
    if 'authority_before' not in operation.record:
        operation.record['authority_before'] = runtime.authority(install, sources)
    else:
        plan.require(runtime.equal(runtime.authority(install, sources), operation.record['authority_before']),
                     'Current security authority changed before publication')
    operation.phase('stopped')
    return sources


def _publish(journal, operation, review):
    install = _install(journal, operation)
    built = review['candidate']
    if not operation.record.get('publication_admitted'):
        _check_original(journal, review)
        _stopped(install, operation, review)
        runtime.verify_files(Path(built['source_directory']), built['source'], closed=True)
        runtime.verify_files(Path(built['artifacts_directory']), built['files'])
        runtime.verify_images(install, built['images'])
        runtime.stage_artifacts(install, operation, built)
        operation.record['source_before'] = storage.inventory(install.source)
        operation.record['source_after'] = storage.inventory(Path(built['source_directory']))
        startup = plan.startup_compose(built['compose'])
        provisional = plan.next_journal(review['original'], operation_id=operation.id,
            source=built['source'], compose=startup,
            packages={name: built['files'][name] for name in plan.NATIVE_FILES},
            guestshell={'state': 'ok', 'scope': 'candidate-only-awaiting-runtime-proof'})
        provisional['state'] = 'APPLICATION_UPGRADE_PENDING'
        operation.record.update(startup_compose=startup, provisional_journal=provisional,
                                publication_admitted=True)
        operation.phase('publishing')
    else:
        plan.require(runtime.equal(journal.document, review['original']) or
                     runtime.equal(journal.document, operation.record['provisional_journal']),
                     'Installation generation changed outside this approved publication')
    # A recorded publication can resume after either rename. No reverse rename
    # or old-code restart is offered after this point.
    for name, staged, before, after in (
        ('source', Path(built['source_directory']), 'source_before', 'source_after'),
        ('artifacts', install.base / ('.upgrade-artifacts-' + operation.id), 'artifact_before', 'artifact_after')):
        storage.publish(install.base / name, staged, install.base / ('.retained-' + name + '-' + operation.id),
                        storage.fingerprint(operation.record[before]),
                        storage.fingerprint(operation.record[after]))
    original = review['compose_before'].encode('utf-8')
    replacement = plan.canonical(operation.record['startup_compose'])
    plan.require(regular_bytes(install.compose_file) in (original, replacement),
                 'Compose publication found unapproved bytes')
    atomic_write(install.compose_file, replacement)
    journal.document = copy.deepcopy(operation.record['provisional_journal'])
    journal.save()
    operation.phase('published', publication_complete=True)


def _service_row(install, operation, service):
    spec = operation.record['candidate']['compose']['services'][service]
    rows = json.loads(install.command(['docker', 'inspect', spec['container_name']], capture=True))
    plan.require(isinstance(rows, list) and len(rows) == 1, 'Cannot resolve one owned service')
    row = rows[0]
    labels = row['Config'].get('Labels', {})
    plan.require(labels.get('com.cisco.iris.installer') == operation.instance
                 and labels.get('com.docker.compose.project') == operation.record['original']['config']['instance']
                 and labels.get('com.docker.compose.service') == service, 'Service ownership changed')
    return row


def _owned_service(install, operation, service):
    """An old exact ID, an acquired new ID, or its durable create intent only."""
    row = _service_row(install, operation, service)
    initial = {item['service']: item for item in operation.record['resources_before']}
    intent = operation.record.get('service_start_intents', {}).get(service)
    if row['Id'] == initial[service]['id']:
        plan.require(row['Image'] in operation.record['original']['completed']['images'].values(),
                     'Original service image changed')
    else:
        plan.require(isinstance(intent, dict) and intent.get('image') == row['Image']
                     and row['Config']['Labels'].get('com.cisco.iris.application-upgrade') == operation.id
                     and (not intent.get('container_id') or intent['container_id'] == row['Id']),
                     'Service identity differs from its recorded start intent')
    return row


def _start_service(install, operation, service):
    built = operation.record['candidate']
    intents = operation.record.setdefault('service_start_intents', {})
    # Record before Compose can replace the old container. An interrupted
    # create can be attributed only by the operation-specific image and label.
    if service not in intents:
        intents[service] = {'image': built['images'][service]}
        operation.save()
    name = built['compose']['services'][service]['container_name']
    present = install.command(['docker', 'container', 'ls', '--all', '--no-trunc',
        '--filter', 'name=^/' + re.escape(name) + '$', '--format', '{{.ID}}'], capture=True).strip()
    if present:
        _owned_service(install, operation, service)
    else:
        # Compose may have removed the original but not created its replacement
        # when interrupted. Only that unacquired creation can resume as absent.
        plan.require(not intents[service].get('container_id'),
                     'An acquired service disappeared outside the recorded transition')
    install.compose('up', '-d', '--no-build', '--no-deps', '--pull', 'never',
                    '--wait', '--wait-timeout', '180', service)
    row = _owned_service(install, operation, service)
    plan.require(row['Image'] == built['images'][service]
                 and row['Config']['Labels'].get('com.cisco.iris.application-upgrade') == operation.id
                 and row['State']['Running'] is True, 'The approved service did not start')
    intents[service]['container_id'] = row['Id']
    operation.save()


def _verify_started(journal, operation, review):
    install = _install(journal, operation)
    built = review['candidate']
    final_journal = plan.next_journal(review['original'], operation_id=operation.id,
        source=built['source'], compose=built['compose'],
        packages={name: built['files'][name] for name in plan.NATIVE_FILES},
        guestshell=operation.record.get('runtime_proof', {}).get('guestshell',
            {'state': 'ok', 'scope': 'not-finalized'}))
    plan.require(runtime.equal(journal.document, operation.record['provisional_journal']) or
                 runtime.equal(journal.document, final_journal), 'The approved journal generation changed')
    # Re-enter restart=no on EVERY recovery, including a crash in final policy
    # publication. This changes only the approved code-generation checkpoints.
    plan.require(regular_bytes(install.compose_file) in (plan.canonical(operation.record['startup_compose']),
                 plan.canonical(built['compose'])), 'The approved Compose generation changed')
    atomic_write(install.compose_file, plan.canonical(operation.record['startup_compose']))
    journal.document = copy.deepcopy(operation.record['provisional_journal'])
    journal.save()
    install.verify_inputs()
    runtime.verify_images(install, built['images'])
    # Restart only the approved new images. The candidate Compose has restart
    # disabled until the operation, including its worker, is verified.
    operation.phase('starting')
    _start_service(install, operation, 'iris')
    operation.phase('verifying')
    runtime.drain(install)
    # Reuse the documented runtime doctor and served bundle validation, but
    # suppress checkpoint writes until the entire transaction is verified.
    original_checkpoint = journal.checkpoint
    checkpoints = {}
    journal.checkpoint = lambda stage, evidence: checkpoints.update({stage: evidence})
    try:
        install.packages()
    finally:
        journal.checkpoint = original_checkpoint
    guest = checkpoints.get('guestshell')
    plan.require(isinstance(guest, dict) and guest.get('state') == 'ok', 'Served Guest Shell verification failed')
    # Producer checks run in a separately created runtime process; they do not
    # bootstrap, replace instruction roots, mint a new owner or initialize an epoch.
    sources = {name: Path(path) for name, path in operation.record['authority_sources'].items()}
    current = runtime.authority(install, sources)
    plan.require(runtime.equal(current, operation.record['authority_before']),
                 'Upgrade changed owner, key, certificate or replay authority; services remain fenced')
    # Expose the Console only after existing owner and security authority have
    # been checked in the new server. Then require a real authenticated hop.
    _start_service(install, operation, 'console')
    sources, volumes, containers = backup.capture_plan(install)
    plan.require(runtime.equal(volumes, review['resources']['volumes']) and all(row['running'] for row in containers),
                 'Upgraded services did not retain the reviewed storage')
    from .credential_maintenance import _consumer_proof
    consumer = _consumer_proof(install)
    plan.require(runtime.equal(runtime.authority(install, sources), operation.record['authority_before']),
                 'Security authority changed during Console startup')
    operation.record.update(runtime_proof={'management': consumer, 'guestshell': guest,
                                           'authority': current}, new_containers=containers)
    operation.phase('worker')


def _fail_stopped(base, operation):
    """Best effort exact-identity fencing; never broad compose down or deletion."""
    problems = []
    try:
        from .upgrade_boot_guard import verify as verify_boot_guard
        verify_boot_guard(base, operation, operation.record['worker_before'])
        runtime.fence_worker(base, operation.record['worker_before'],
            new_runtime=operation.record['candidate']['selection']['runtime']
            if operation.record.get('publication_admitted') else None)
    except (InstallError, OSError, ValueError):
        problems.append('worker-fence-unconfirmed')
    try:
        with Journal(base).locked() as journal:
            install = _install(journal, operation)
            # Name lookup alone never authorizes a stop. Prefer acquired exact
            # IDs; only a recorded in-flight creation may use its unique label.
            for service in plan.SERVICES:
                try:
                    row = _owned_service(install, operation, service)
                    install.command(['docker', 'update', '--restart=no', row['Id']])
                    install.command(['docker', 'stop', '--time', '120', row['Id']], timeout=180)
                except (InstallError, OSError, ValueError, KeyError):
                    problems.append(service + '-fence-unconfirmed')
    except (InstallError, OSError, ValueError, KeyError):
        problems.append('service-fence-unconfirmed')
    operation.phase('recovery-required', problems=problems)


def apply(args, *, recovery=False):
    base = _root(args.state_dir)
    plan.require(args.allow_downtime, 'Confirm downtime with --allow-downtime')
    with managed_worker._service_lock(base):
        with Journal(base).locked() as journal:
            operation = Operation(base, args.operation_id, journal.document['id'])
            operation.load(recover=recovery)
            review = operation.plan(args.plan_sha256)
            plan.require(review.get('schema') == plan.SCHEMA
                and runtime.equal(operation.record.get('original'), review.get('original'))
                and runtime.equal(operation.record.get('candidate'), review.get('candidate'))
                and runtime.equal(operation.record.get('worker_before'), review.get('worker_before')),
                'Operation authority differs from its reviewed immutable plan')
            if operation.record['phase'] == 'upgraded':
                print(json.dumps({'operation_id': operation.id, 'phase': 'upgraded'}))
                return 0
            plan.require(recovery or operation.record['phase'] == 'prepared',
                         'Use upgrade recover with the original operation ID and plan digest')
            if 'fence_intent' not in operation.record:
                _check_original(journal, review)
                _idle(journal, operation_id=operation.id)
                install = _install(journal, operation)
                backup.capture_plan(install)
                runtime.drain(install)
                from .upgrade_boot_guard import install as install_boot_guard
                install_boot_guard(base, operation, review['worker_before'])
                operation.phase('fencing', fence_intent=review['worker_before'],
                                resources_before=review['resources']['containers'])
            plan.require(runtime.equal(operation.record.get('resources_before'), review['resources']['containers']),
                         'The recorded service preimage differs from the reviewed plan')
        try:
            from .upgrade_boot_guard import verify as verify_boot_guard
            verify_boot_guard(base, operation, review['worker_before'])
            # Revalidate and fence again after a restart; a historical proof
            # does not establish the current service state.
            result = runtime.fence_worker(base, review['worker_before'],
                new_runtime=review['candidate']['selection']['runtime'] if operation.record.get('publication_admitted') else None)
            operation.record['worker_fenced'] = result
            operation.save()
            if not operation.record.get('publication_admitted'):
                with Journal(base).locked() as journal:
                    _check_original(journal, review)
                    install = _install(journal, operation)
                    runtime.disable_restarts(install, review['resources']['containers'])
                if 'backup' not in operation.record:
                    operation.phase('backing-up')
                    operation.record['backup'] = runtime.capture_and_verify(base, operation, review['worker_before'])
                    operation.save()
                else:
                    runtime.verify_backup(base, operation.record['backup']['paths'], review['worker_before']['record'])
                with Journal(base).locked() as journal:
                    _publish(journal, operation, review)
            elif not operation.record.get('publication_complete'):
                with Journal(base).locked() as journal:
                    _publish(journal, operation, review)
            with Journal(base).locked() as journal:
                _verify_started(journal, operation, review)
            operation.record['worker_after'] = runtime.refresh_worker(base, operation, review['worker_before'])
            verify_boot_guard(base, operation, review['worker_before'])
            operation.phase('finishing')
            with Journal(base).locked() as journal:
                install = _install(journal, operation)
                final_compose = review['candidate']['compose']
                final_journal = plan.next_journal(review['original'], operation_id=operation.id,
                    source=review['candidate']['source'], compose=final_compose,
                    packages={name: review['candidate']['files'][name] for name in plan.NATIVE_FILES},
                    guestshell=operation.record['runtime_proof']['guestshell'])
                plan.require(runtime.equal(journal.document, operation.record['provisional_journal']) or
                             runtime.equal(journal.document, final_journal), 'Final journal has unapproved changes')
                current = regular_bytes(install.compose_file)
                plan.require(current in (plan.canonical(operation.record['startup_compose']), plan.canonical(final_compose)),
                             'Final Compose generation changed')
                atomic_write(install.compose_file, plan.canonical(final_compose))
                journal.document = final_journal
                journal.save()
                # Exact containers only; enabling restart is last, after all
                # application checks and the new guarded worker are healthy.
                for row in operation.record['new_containers']:
                    policy = final_compose['services'][row['service']].get('restart', 'no')
                    observed = _owned_service(install, operation, row['service'])
                    plan.require(observed['Id'] == row['id'], 'Verified service was replaced before finalization')
                    install.command(['docker', 'update', '--restart=' + policy, row['id']])
                    observed = _owned_service(install, operation, row['service'])
                    plan.require(observed['HostConfig']['RestartPolicy']['Name'] == policy
                                 and observed['State']['Running'] is True,
                                 'Verified service restart policy or running state changed')
                operation.phase('upgraded')
            print(json.dumps({'operation_id': operation.id, 'phase': 'upgraded',
                              'source_commit': review['candidate']['selection']['commit'],
                              'device_action': 'onboard-again'}, sort_keys=True))
            return 0
        except BaseException:
            _fail_stopped(base, operation)
            raise


def status(args):
    base = _root(args.state_dir)
    with Journal(base).locked() as journal:
        guard(base, instance_id=journal.document['id'], inspection=True)
        path = base / 'application-upgrade.json'
        if not path.exists():
            print(json.dumps({'phase': 'none'}))
        else:
            value = read(path)
            operation = Operation(base, value['operation_id'], journal.document['id'])
            operation.load()
            print(json.dumps({name: operation.record.get(name) for name in
                ('operation_id', 'instance_id', 'phase', 'plan_sha256', 'problems')}, sort_keys=True))
    return 0
