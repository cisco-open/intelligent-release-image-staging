#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Revalidate an explicitly selected unsigned prebuilt stage before attestation.

Only fixed-repository GETs occur externally. Candidate programs and builders are
never executed. Reviewer attribution and independently supplied validation roots
remain caller decisions; this helper neither grants approval nor publishes.
"""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat
import tempfile

from iris_installer import prebuilt_release as gate, release_kit as kit
from iris_installer.state import InstallError, regular_bytes

INCOMING_RECORD = 'prebuilt-incoming.json'
SCHEMA = 'iris-hosted-prebuilt-input-v1'


def fail(message):
    raise InstallError('Hosted prebuilt stage: ' + message)


def stage_helper():
    # Load only the trusted checkout helper, never the copy from incoming data.
    path = Path(__file__).with_name('release-stage.py')
    spec = importlib.util.spec_from_file_location('iris_trusted_hosted_stage', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def _file_at(directory, name):
    """Hash a leaf beneath the producer's held staging FD, not its proc alias."""
    kit._name(name)
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.geteuid() or before.st_mode & 0o022
                or not 0 < before.st_size <= kit.MAX_ASSET):
            fail('staged asset must be a protected bounded owned regular file')
        def identity(info):
            return (*kit._identity(info), info.st_uid, info.st_gid, info.st_mode, info.st_nlink)
        digest, size = kit._hash(descriptor, kit.MAX_ASSET)
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (size != before.st_size or identity(before) != identity(os.fstat(descriptor))
                or identity(before) != identity(named)):
            fail('staged asset changed while being inventoried')
        return {'sha256': digest, 'size': size}
    finally:
        os.close(descriptor)


def _inventory(stage):
    # _publication intentionally exposes a /proc/self/fd path under its held
    # parent. Public-input path guards must stay strict; hash this private output
    # through an independently held child descriptor instead.
    directory = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        identity = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)
        named = stage.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077
                or (named.st_dev, named.st_ino, named.st_uid, named.st_gid, named.st_mode) != identity):
            fail('staging directory must remain caller-owned and private')
        names = set(os.listdir(directory))
        if not 0 < len(names) <= kit.MAX_ASSETS:
            fail('staging directory exceeds the bounded asset inventory')
        rows = {name: _file_at(directory, name) for name in sorted(names)}
        gate._asset_map(rows)
        if set(os.listdir(directory)) != names:
            fail('staged asset set changed during inventory')
        named = stage.lstat()
        current = os.fstat(directory)
        if ((named.st_dev, named.st_ino, named.st_uid, named.st_gid, named.st_mode) != identity
                or (current.st_dev, current.st_ino, current.st_uid, current.st_gid, current.st_mode) != identity):
            fail('staging directory changed during inventory')
        return rows
    finally:
        os.close(directory)


def _write_metadata(stage, name, raw):
    kit._name(name)
    directory = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
    finally:
        os.close(directory)


def selection(*, tag, commit, profile, run_id, run_attempt, artifact_id, artifact_sha256,
              evidence_sha256, review_sha256, keyring_sha256, pip_sdist_sha256):
    stage = stage_helper()
    if profile not in kit.PROFILES:
        fail('select an explicit supported prebuilt profile')
    selected = stage.selection(tag, commit, run_id, run_attempt, artifact_id, artifact_sha256)
    selected.update(profile=profile, candidate_evidence_sha256=kit._sha(evidence_sha256),
                    source_review_sha256=kit._sha(review_sha256),
                    external_pins={'debian_keyring_sha256': kit._sha(keyring_sha256),
                                   'pip_sdist_sha256': kit._sha(pip_sdist_sha256)})
    return selected


def origin(stage, selected, token):
    run = stage._api(f"/actions/runs/{selected['run_id']}/attempts/{selected['run_attempt']}", token)
    if (not isinstance(run, dict) or type(run.get('id')) is not int or run['id'] != selected['run_id']
            or type(run.get('run_attempt')) is not int or run['run_attempt'] != selected['run_attempt']
            or run.get('head_sha') != selected['commit'] or run.get('status') != 'completed'
            or run.get('conclusion') != 'success' or run.get('event') not in ('push', 'workflow_dispatch')
            or not isinstance(run.get('path'), str) or not re.fullmatch(r'\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml(?:@[^\s]+)?', run['path'])):
        fail('incoming run identity or completion differs')
    repository, head = run.get('repository'), run.get('head_repository')
    if (not isinstance(repository, dict) or not isinstance(head, dict)
            or repository.get('full_name') != stage.REPOSITORY or head.get('full_name') != stage.REPOSITORY
            or stage._positive(repository.get('id')) != stage._positive(head.get('id'))):
        fail('incoming run is not from the fixed repository')
    artifact = stage._api(f"/actions/artifacts/{selected['artifact_id']}", token)
    if (not isinstance(artifact, dict) or type(artifact.get('id')) is not int
            or artifact['id'] != selected['artifact_id'] or artifact.get('expired') is not False
            or artifact.get('digest') != 'sha256:' + selected['artifact_sha256']
            or type(artifact.get('size_in_bytes')) is not int or not 0 < artifact['size_in_bytes'] <= stage.MAX_TOTAL
            or not isinstance(artifact.get('name'), str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,255}', artifact['name'])):
        fail('incoming artifact identity, digest or bounds differ')
    parent = artifact.get('workflow_run')
    if (not isinstance(parent, dict) or type(parent.get('id')) is not int or parent['id'] != run['id']
            or parent.get('head_sha') != selected['commit']
            or type(parent.get('repository_id')) is not int or parent['repository_id'] != repository['id']
            or type(parent.get('head_repository_id')) is not int or parent['head_repository_id'] != repository['id']):
        fail('incoming artifact belongs to a different run or repository')
    return {'run_id': run['id'], 'run_attempt': run['run_attempt'], 'workflow': run['path'],
            'event': run['event'], 'repository_id': repository['id'], 'artifact_id': artifact['id'],
            'artifact_name': artifact['name'], 'artifact_sha256': selected['artifact_sha256'],
            'artifact_size': artifact['size_in_bytes']}


def _completed(incoming, files, selected, destination):
    """Recover exactly the original completed subset, not arbitrary extra files."""
    stage = stage_helper()
    evidence_raw = regular_bytes(incoming / gate.completion.MANIFEST, kit.MAX_METADATA)
    if hashlib.sha256(evidence_raw).hexdigest() != selected['candidate_evidence_sha256']:
        fail('candidate evidence differs from its independent selection')
    evidence = kit._json(evidence_raw)
    kit._keys(evidence, gate.EVIDENCE_FIELDS)
    if (evidence['profile'] != selected['profile'] or evidence['tag'] != selected['tag']
            or evidence['commit'] != selected['commit'] or evidence['external_pins'] != selected['external_pins']):
        fail('candidate profile or independent validation roots differ')
    gate._asset_map(evidence['files'])
    inventory = kit._json(regular_bytes(incoming / 'release.json', kit.MAX_METADATA))
    kit._keys(inventory, {'schema', 'repository', 'workflow', 'tag', 'commit', 'assets'})
    expected_assets = {name: row for name, row in files.items() if name not in ('release.json', 'SHA256SUMS')}
    if (type(inventory['schema']) is not int or inventory['schema'] != 1
            or inventory['repository'] != stage.REPOSITORY or inventory['workflow'] != stage.WORKFLOW
            or inventory['tag'] != selected['tag'] or inventory['commit'] != selected['commit']
            or inventory['assets'] != expected_assets):
        fail('unsigned inventory differs from its exact payload')
    expected_checksums = ''.join(files[name]['sha256'] + '  ' + name + '\n'
                                 for name in sorted(files) if name != 'SHA256SUMS').encode()
    if regular_bytes(incoming / 'SHA256SUMS', kit.MAX_METADATA) != expected_checksums:
        fail('unsigned checksum list differs from its exact payload')
    # The old producer's complete flat payload is checked before any context is
    # rebound. No unsigned claim is treated as authentication or source review.
    previous_raw = regular_bytes(incoming / gate.STAGE_NAME, kit.MAX_METADATA)
    previous = gate._stage(previous_raw, selected['tag'], selected['commit'])
    if any(previous[key] != selected[key] for key in ('run_id', 'run_attempt')):
        fail('unsigned preparation does not bind its actual incoming run attempt')
    prior = dict(selected, run_id=previous['run_id'], run_attempt=previous['run_attempt'])
    stage._prebuilt_metadata(incoming, files, prior, selected['profile'], require_incoming=False, unsigned=True)
    if hashlib.sha256(regular_bytes(incoming / gate.REVIEW_NAME, kit.MAX_METADATA)).hexdigest() != selected['source_review_sha256']:
        fail('source review differs from its independent selection')
    destination.mkdir(mode=0o700)
    names = {*evidence['files'], gate.completion.MANIFEST}
    for name in sorted(names):
        pin = files[name]['sha256']
        if kit._snapshot(incoming / name, destination / name, kit.MAX_ASSET) != pin:
            fail('completed input changed during reconstruction')
    return evidence


def prepare(selected, *, repository, output_dir, keyring, current_run_id, current_run_attempt,
            ref, confirmation, token=None):
    """Full existing candidate validation and unsigned re-seal; no attestation."""
    stage = stage_helper()
    kit._keys(selected, {'tag', 'commit', 'run_id', 'run_attempt', 'artifact_id', 'artifact_sha256',
                         'profile', 'candidate_evidence_sha256', 'source_review_sha256', 'external_pins'})
    kit._keys(selected['external_pins'], {'debian_keyring_sha256', 'pip_sdist_sha256'})
    if ref != 'refs/tags/' + selected['tag']:
        fail('authentication must run on the exact selected release tag')
    if confirmation != 'authenticate ' + selected['tag'] + ' ' + selected['candidate_evidence_sha256']:
        fail('explicit exact-candidate authentication confirmation required')
    current_run_id, current_run_attempt = stage._positive(current_run_id), stage._positive(current_run_attempt)
    selected = selection(tag=selected['tag'], commit=selected['commit'], profile=selected['profile'],
        run_id=selected['run_id'], run_attempt=selected['run_attempt'], artifact_id=selected['artifact_id'],
        artifact_sha256=selected['artifact_sha256'], evidence_sha256=selected['candidate_evidence_sha256'],
        review_sha256=selected['source_review_sha256'], keyring_sha256=selected['external_pins']['debian_keyring_sha256'],
        pip_sdist_sha256=selected['external_pins']['pip_sdist_sha256'])
    stage._current_tag(selected, token)
    incoming_origin = origin(stage, selected, token)
    # Git parity is checked again by the full existing producer. Never execute
    # incoming code, select a keyring from the ZIP, or import its verifier.
    gate._git_selection(repository, selected['tag'], selected['commit'])
    output_dir = kit._path(output_dir)
    descriptor = kit._protected_directory(output_dir.parent)
    try:
        if os.fstat(descriptor).st_uid != os.geteuid() or os.path.lexists(output_dir):
            fail('select a new output under a protected caller-owned parent')
    finally:
        os.close(descriptor)
    with tempfile.TemporaryDirectory(prefix='.iris-hosted-prebuilt-', dir=output_dir.parent) as temporary:
        work = Path(temporary); work.chmod(0o700)
        archive, incoming = work / 'incoming.zip', work / 'incoming'
        incoming.mkdir(mode=0o700)
        stage._download(selected, archive, incoming_origin['artifact_size'], token)
        files = stage._unpack(archive, incoming)
        if 'attestations.jsonl' in files or INCOMING_RECORD in files:
            fail('incoming preparation must be unsigned, not a previous hosted stage')
        evidence = _completed(incoming, files, selected, work / 'completed')
        keyring_copy = work / 'independent-debian-keyring.gpg'
        if kit._snapshot(kit._path(keyring), keyring_copy, kit.MAX_METADATA) != selected['external_pins']['debian_keyring_sha256']:
            fail('independently supplied Debian keyring changed')
        review = work / gate.REVIEW_NAME
        if kit._snapshot(incoming / gate.REVIEW_NAME, review, kit.MAX_METADATA) != selected['source_review_sha256']:
            fail('independently selected review changed')
        record = work / gate.STAGE_NAME
        stage.create_stage_record(record, selected['tag'], selected['commit'], current_run_id, current_run_attempt)
        with gate._publication(output_dir) as (sealed, final):
            prepared = work / 'prepared'
            gate.prepare_prebuilt(work / 'completed', selected['candidate_evidence_sha256'], prepared,
                repository=repository, tag=selected['tag'], commit=selected['commit'],
                debian_keyring=keyring_copy, pip_sdist_sha256=selected['external_pins']['pip_sdist_sha256'],
                source_review=review, expected_review_sha256=selected['source_review_sha256'],
                stage_record=record, expected_stage_sha256=hashlib.sha256(regular_bytes(record)).hexdigest())
            for path in sorted(prepared.iterdir()):
                if path.name in ('release.json', 'SHA256SUMS'):
                    continue
                kit._snapshot(path, sealed / path.name, kit.MAX_ASSET)
            incoming_record = {'schema': SCHEMA, 'repository': stage.REPOSITORY,
                **{key: selected[key] for key in ('tag', 'commit', 'profile', 'candidate_evidence_sha256', 'source_review_sha256', 'external_pins')},
                'incoming': incoming_origin, 'hosted_run': {'run_id': current_run_id, 'run_attempt': current_run_attempt},
                'review_authority_verified': False, 'payloads_rebuilt': False}
            _write_metadata(sealed, INCOMING_RECORD, stage._canonical(incoming_record))
            assets = _inventory(sealed)
            inventory = {'schema': 1, 'repository': stage.REPOSITORY, 'workflow': stage.WORKFLOW,
                         'tag': selected['tag'], 'commit': selected['commit'], 'assets': assets}
            _write_metadata(sealed, 'release.json', stage._canonical(inventory))
            checks = _inventory(sealed)
            _write_metadata(sealed, 'SHA256SUMS', ''.join(checks[name]['sha256'] + '  ' + name + '\n' for name in sorted(checks)).encode())
            # Ensure all original completed bytes and the approved review remain
            # exact. Only stage/preparation/inventory context has been rebound.
            final_assets = _inventory(sealed)
            if set(final_assets) != {*checks, 'SHA256SUMS'}:
                fail('staged asset set changed before publication')
            for name, row in assets.items():
                if final_assets[name] != row:
                    fail('inventory-bound asset changed before publication')
            for name, row in checks.items():
                if final_assets[name] != row:
                    fail('staged asset changed before publication')
            for name, row in evidence['files'].items():
                if final_assets[name] != row:
                    fail('approved payload changed during hosted preparation')
            if final_assets[gate.REVIEW_NAME]['sha256'] != selected['source_review_sha256']:
                fail('approved review bytes changed')
            stage._current_tag(selected, token)
    return output_dir


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--debian-keyring', type=Path, required=True)
    for name in ('tag', 'commit', 'profile', 'artifact-sha256', 'evidence-sha256', 'review-sha256',
                 'keyring-sha256', 'pip-sdist-sha256', 'ref', 'confirmation'):
        parser.add_argument('--' + name, required=True)
    for name in ('incoming-run-id', 'incoming-run-attempt', 'artifact-id', 'run-id', 'run-attempt'):
        parser.add_argument('--' + name, type=int, required=True)
    args = parser.parse_args()
    try:
        selected = selection(tag=args.tag, commit=args.commit, profile=args.profile,
            run_id=args.incoming_run_id, run_attempt=args.incoming_run_attempt, artifact_id=args.artifact_id,
            artifact_sha256=args.artifact_sha256, evidence_sha256=args.evidence_sha256,
            review_sha256=args.review_sha256, keyring_sha256=args.keyring_sha256, pip_sdist_sha256=args.pip_sdist_sha256)
        prepare(selected, repository=args.repository.resolve(), output_dir=args.output_dir.resolve(),
                keyring=args.debian_keyring.resolve(), current_run_id=args.run_id, current_run_attempt=args.run_attempt,
                ref=args.ref, confirmation=args.confirmation, token=os.environ.get('GH_TOKEN'))
        print('Validated unsigned prebuilt inputs; hosted authentication and qualification remain separate.')
        return 0
    except (InstallError, OSError, ValueError, KeyError, TypeError):
        print('Hosted prebuilt preparation refused; no asset was authenticated or published.')
        return 1


if __name__ == '__main__': raise SystemExit(main())
