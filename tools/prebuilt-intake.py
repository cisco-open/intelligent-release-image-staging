#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Transfer exact reviewed candidate bytes through a dedicated draft intake.

Plan is read-only externally. Upload needs a separate exact confirmation and
records intent before every POST; an uncertain POST is reconciled, never replayed.
Hosted prepare performs fixed-repository GETs and full source validation only.
No command creates/publishes a release, changes a tag, signs, deletes or rebuilds.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
import urllib.parse

from iris_installer import prebuilt_release as gate, release_kit as kit
from iris_installer.state import InstallError, atomic_write, regular_bytes

PLAN = 'intake-plan.json'
STATE = 'intake-upload-state.json'
MANIFEST = 'prebuilt-intake.json'
SCHEMA = 'iris-prebuilt-intake-v1'
PLAN_FIELDS = {'schema', 'repository', 'tag', 'commit', 'profile', 'draft', 'files',
               'candidate_evidence_sha256', 'source_review_sha256', 'external_pins', 'local_root'}
INTAKE_FIELDS = PLAN_FIELDS - {'local_root'}


def fail(message):
    raise InstallError('Prebuilt intake: ' + message)


def helper(name):
    # Only reviewed code beside this helper; no program comes from the intake.
    spec = importlib.util.spec_from_file_location('iris_intake_' + name, Path(__file__).with_name(name))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def _limits(files):
    gate._asset_map(files)
    stage = helper('release-stage.py')
    if (len(files) > stage.MAX_FILES or sum(row['size'] for row in files.values()) > stage.MAX_TOTAL
            or any(row['size'] >= 2 * 1024**3 for row in files.values())):
        fail('intake exceeds per-asset or total release bounds')


def _draft(stage, release_id, tag, commit, evidence_sha256, token):
    stage._positive(release_id)
    value = stage._api('/releases/' + str(release_id), token)
    name = 'iris-prebuilt-intake-' + kit._sha(evidence_sha256)[:16]
    if (not isinstance(value, dict) or type(value.get('id')) is not int or value['id'] != release_id
            or value.get('draft') is not True or value.get('published_at') is not None
            or value.get('tag_name') != name or value['tag_name'] == tag
            or value.get('target_commitish') != commit):
        fail('select the existing dedicated unpublished draft for these exact bytes')
    return {'id': release_id, 'tag_name': name, 'target_commitish': commit}


def _assets(stage, release_id, token):
    rows = stage._api('/releases/' + str(release_id) + '/assets?per_page=100', token)
    if not isinstance(rows, list) or len(rows) > stage.MAX_FILES + 1:
        fail('draft asset census exceeds the closed intake bound')
    result = {}
    ids = set()
    for row in rows:
        if not isinstance(row, dict): fail('draft asset metadata is invalid')
        asset_id = stage._positive(row.get('id'))
        name = kit._name(row.get('name'))
        if name in result or asset_id in ids: fail('draft contains ambiguous assets')
        ids.add(asset_id); result[name] = row
    return result


def _row(stage, value, name, expected):
    if (not isinstance(value, dict) or value.get('name') != name or value.get('state') != 'uploaded'
            or type(value.get('size')) is not int or value['size'] != expected['size']
            or value.get('digest') != 'sha256:' + expected['sha256']):
        fail('remote asset differs from its exact selected bytes')
    return {'id': stage._positive(value.get('id')), **expected}


def plan(directory, evidence_sha256, output_dir, *, repository, tag, commit, profile,
         source_review, review_sha256, debian_keyring, keyring_sha256, pip_sdist_sha256,
         draft_release_id, token=None):
    """Snapshot fully checked inputs locally; only read the existing draft."""
    stage = helper('release-stage.py')
    stage.selection(tag, commit, 1, 1, 1, '0' * 64)
    if profile not in kit.PROFILES: fail('select an explicit prebuilt profile')
    pins = {'debian_keyring_sha256': kit._sha(keyring_sha256),
            'pip_sdist_sha256': kit._sha(pip_sdist_sha256)}
    kit._sha(evidence_sha256); kit._sha(review_sha256)
    stage._current_tag({'tag': tag, 'commit': commit}, token)
    draft = _draft(stage, draft_release_id, tag, commit, evidence_sha256, token)
    if _assets(stage, draft_release_id, token): fail('a new intake plan requires an empty dedicated draft')
    with tempfile.TemporaryDirectory(prefix='.iris-intake-plan-', dir=kit._path(output_dir).parent) as temporary:
        work = Path(temporary)
        keyring_copy, review = work / 'keyring.gpg', work / 'review.json'
        if kit._snapshot(kit._path(debian_keyring), keyring_copy, kit.MAX_METADATA) != pins['debian_keyring_sha256']:
            fail('independent Debian keyring differs')
        if kit._snapshot(kit._path(source_review), review, kit.MAX_METADATA) != review_sha256:
            fail('independently selected source review differs')
        evidence_copy = work / gate.completion.MANIFEST
        if kit._snapshot(kit._path(directory) / gate.completion.MANIFEST, evidence_copy, kit.MAX_METADATA) != evidence_sha256:
            fail('candidate evidence differs from its independent selection')
        evidence = kit._json(regular_bytes(evidence_copy, kit.MAX_METADATA))
        kit._keys(evidence, gate.EVIDENCE_FIELDS)
        if (evidence['profile'] != profile or evidence['external_pins'] != pins
                or (evidence['tag'], evidence['commit']) != (tag, commit)):
            fail('candidate differs from independent profile, source or validation roots')
        with gate._publication(output_dir) as (sealed, _), gate.check_completed_candidate(
                directory, evidence_sha256, repository=repository, tag=tag, commit=commit,
                debian_keyring=keyring_copy, pip_sdist_sha256=pip_sdist_sha256) as checked:
            if checked.evidence['profile'] != profile or checked.evidence['external_pins'] != pins:
                fail('candidate differs from the independently selected profile or roots')
            gate._review(regular_bytes(review, kit.MAX_METADATA), checked, tag=tag, commit=commit)
            files = {**checked.evidence['files'], gate.completion.MANIFEST: {
                'sha256': evidence_sha256, 'size': (checked.directory / gate.completion.MANIFEST).stat().st_size},
                gate.REVIEW_NAME: {'sha256': review_sha256, 'size': review.stat().st_size}}
            if set(files) & {PLAN, STATE, MANIFEST, 'lock'}: fail('candidate uses reserved intake names')
            _limits(files)
            for name, expected in files.items():
                source = review if name == gate.REVIEW_NAME else checked.directory / name
                if (kit._snapshot(source, sealed / name, kit.MAX_ASSET) != expected['sha256']
                        or (sealed / name).stat().st_size != expected['size']):
                    fail('checked input changed during local snapshot')
            info = sealed.stat()
            record = {'schema': SCHEMA, 'repository': stage.REPOSITORY, 'tag': tag, 'commit': commit,
                'profile': profile, 'draft': draft, 'files': files, 'external_pins': pins,
                'candidate_evidence_sha256': evidence_sha256, 'source_review_sha256': review_sha256,
                'local_root': {'device': info.st_dev, 'inode': info.st_ino}}
            (sealed / PLAN).write_bytes(stage._canonical(record))
            initial = {'schema': SCHEMA, 'plan_sha256': hashlib.sha256(stage._canonical(record)).hexdigest(),
                       'uploaded': {}, 'pending': None}
            (sealed / STATE).write_bytes(stage._canonical(initial))
            if _assets(stage, draft_release_id, token): fail('draft changed during planning')
            if _draft(stage, draft_release_id, tag, commit, evidence_sha256, token) != draft:
                fail('draft identity changed during planning')
            stage._current_tag(record, token)
    return {'plan_sha256': hashlib.sha256(stage._canonical(record)).hexdigest(), 'draft_release_id': draft_release_id}


def _validate_plan(value):
    stage = helper('release-stage.py')
    kit._keys(value, PLAN_FIELDS)
    if value['schema'] != SCHEMA or value['repository'] != stage.REPOSITORY or value['profile'] not in kit.PROFILES:
        fail('unsupported intake plan')
    stage.selection(value['tag'], value['commit'], 1, 1, 1, '0' * 64)
    kit._keys(value['draft'], {'id', 'tag_name', 'target_commitish'})
    stage._positive(value['draft']['id'])
    if (value['draft']['tag_name'] != 'iris-prebuilt-intake-' + kit._sha(value['candidate_evidence_sha256'])[:16]
            or value['draft']['target_commitish'] != value['commit']): fail('draft plan identity differs')
    kit._sha(value['source_review_sha256'])
    kit._keys(value['external_pins'], {'debian_keyring_sha256', 'pip_sdist_sha256'})
    for pin in value['external_pins'].values(): kit._sha(pin)
    kit._keys(value['local_root'], {'device', 'inode'})
    if any(type(item) is not int or not 0 <= item < 2**64 for item in value['local_root'].values()):
        fail('invalid local intake directory identity')
    _limits(value['files'])
    if set(value['files']) & {PLAN, STATE, MANIFEST, 'lock'}: fail('reserved intake asset')
    if (value['files'].get(gate.completion.MANIFEST, {}).get('sha256') != value['candidate_evidence_sha256']
            or value['files'].get(gate.REVIEW_NAME, {}).get('sha256') != value['source_review_sha256']):
        fail('candidate and review selection differ from the planned bytes')
    return stage


@contextmanager
def _locked(directory, expected):
    hosted = helper('hosted-prebuilt-stage.py')
    directory = kit._path(directory)
    descriptor = kit._protected_directory(directory)
    lock = None
    try:
        info = os.fstat(descriptor)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            fail('intake state must be caller-owned and private')
        lock = os.open('lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
        info = os.fstat(lock)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600): fail('unsafe intake lock')
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: fail('another intake operation holds this plan')
        row = hosted._file_at(descriptor, PLAN)
        if row['sha256'] != kit._sha(expected): fail('local plan differs from its independent selection')
        held = Path('/proc/self/fd') / str(descriptor)
        raw = regular_bytes(held / PLAN, kit.MAX_METADATA)
        if hashlib.sha256(raw).hexdigest() != expected: fail('plan changed before parsing')
        value = kit._json(raw)
        _validate_plan(value)
        info = os.fstat(descriptor)
        if value['local_root'] != {'device': info.st_dev, 'inode': info.st_ino}:
            fail('intake state directory was replaced or copied; preserve the original intent')
        names = set(os.listdir(descriptor))
        if len(names) > kit.MAX_ASSETS: fail('intake state exceeds its bounded census')
        for name in names - {*value['files'], PLAN, STATE, MANIFEST, 'lock'}:
            scratch = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            # atomic_write may leave an inert mkstemp leaf on abrupt process
            # death. Never read, adopt or delete it; it supplies no authority.
            if (not re.fullmatch(r'\.iris-[a-z0-9_]{8}', name) or not stat.S_ISREG(scratch.st_mode)
                    or scratch.st_uid != os.geteuid() or scratch.st_nlink != 1
                    or stat.S_IMODE(scratch.st_mode) != 0o600 or not 0 <= scratch.st_size <= kit.MAX_METADATA):
                fail('intake state contains untracked files; preserve it for inspection')
        for name, expected_row in value['files'].items():
            if hosted._file_at(descriptor, name) != expected_row: fail('planned bytes changed')
        yield held, descriptor, value
        current = directory.lstat(); held_info = os.fstat(descriptor)
        if (current.st_dev, current.st_ino) != (held_info.st_dev, held_info.st_ino): fail('intake directory changed')
    finally:
        if lock is not None: os.close(lock)
        os.close(descriptor)


def _manifest(plan, uploaded):
    return {**{key: plan[key] for key in INTAKE_FIELDS - {'files'}},
            'files': {name: uploaded[name] for name in plan['files']}}


def _state(held, descriptor, plan_sha256, planned):
    state_path = held / STATE
    # Published by plan before any POST. Never recreate missing state: it could
    # have contained a pending upload whose external outcome is still unknown.
    helper('hosted-prebuilt-stage.py')._file_at(descriptor, STATE)
    value = kit._json(regular_bytes(state_path, kit.MAX_METADATA))
    kit._keys(value, {'schema', 'plan_sha256', 'uploaded', 'pending'})
    if value['schema'] != SCHEMA or value['plan_sha256'] != plan_sha256 or not isinstance(value['uploaded'], dict):
        fail('upload state differs from its immutable plan')
    if set(value['uploaded']) - {*planned, MANIFEST}: fail('upload state has unplanned assets')
    if MANIFEST in value['uploaded'] and not set(planned) <= value['uploaded'].keys(): fail('manifest precedes payloads')
    stage = helper('release-stage.py')
    ids = set()
    for name, row in value['uploaded'].items():
        kit._keys(row, {'id', 'sha256', 'size'})
        asset_id = stage._positive(row['id'])
        if asset_id in ids: fail('upload state aliases asset IDs')
        ids.add(asset_id); kit._sha(row['sha256'])
        if type(row['size']) is not int or not 0 < row['size'] < 2 * 1024**3: fail('upload state has invalid size')
        if name in planned and {key: row[key] for key in ('sha256', 'size')} != planned[name]: fail('uploaded bytes differ')
    pending = value['pending']
    if pending is not None:
        kit._keys(pending, {'name', 'sha256', 'size', 'known_ids'})
        if pending['name'] not in {*planned, MANIFEST} or pending['name'] in value['uploaded']: fail('unplanned pending upload')
        if pending['known_ids'] != sorted(ids): fail('pending upload baseline differs')
        kit._sha(pending['sha256'])
        if type(pending['size']) is not int or not 0 < pending['size'] < 2 * 1024**3: fail('invalid pending upload bounds')
        if pending['name'] in planned and {key: pending[key] for key in ('sha256', 'size')} != planned[pending['name']]:
            fail('pending upload differs from its exact plan')
        if pending['name'] == MANIFEST and not set(planned) <= value['uploaded'].keys(): fail('pending manifest precedes payloads')
    return value


def _remote_state(stage, plan, state, token):
    if _draft(stage, plan['draft']['id'], plan['tag'], plan['commit'], plan['candidate_evidence_sha256'], token) != plan['draft']:
        fail('draft changed')
    assets = _assets(stage, plan['draft']['id'], token)
    allowed = set(state['uploaded'])
    if state['pending'] is not None: allowed.add(state['pending']['name'])
    if set(assets) - allowed: fail('draft contains foreign or unplanned assets')
    for name, row in state['uploaded'].items():
        actual = _row(stage, assets.get(name), name, {key: row[key] for key in ('sha256', 'size')})
        if actual != row: fail('a completed upload was replaced')
    return assets


def _post(gh, release_id, name, descriptor):
    stage = helper('release-stage.py')
    endpoint = 'https://uploads.github.com/repos/' + stage.REPOSITORY + '/releases/' + str(release_id) + '/assets?name=' + urllib.parse.quote(name)
    environment = dict(os.environ, GH_HOST='github.com', GH_PROMPT_DISABLED='1')
    # Exact inherited input FD; no source pathname or token enters arguments.
    with tempfile.TemporaryFile() as output:
        subprocess.run([str(gh), 'api', '--hostname', 'github.com', '--method', 'POST', endpoint,
            '--header', 'Content-Type: application/octet-stream', '--input', '/proc/self/fd/' + str(descriptor)],
            stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
            timeout=900, check=True, env=environment, pass_fds=(descriptor,))
        output.seek(0); raw = output.read(stage.MAX_JSON + 1)
        if len(raw) > stage.MAX_JSON: fail('upload response exceeds its bound; reconcile original intent')
        return kit._json(raw)


def upload(directory, plan_sha256, *, github_cli, confirmation, token=None):
    """Resume exact uploads; an uncertain pending POST is never issued again."""
    if confirmation != 'upload prebuilt intake ' + kit._sha(plan_sha256): fail('explicit exact-plan upload confirmation required')
    with _locked(directory, plan_sha256) as (held, descriptor, planned):
        stage = _validate_plan(planned)
        gh, _ = kit._verifier(kit._path(github_cli), kit._path(directory))
        state = _state(held, descriptor, plan_sha256, planned['files'])
        assets = _remote_state(stage, planned, state, token)
        if state['pending'] is not None:
            pending = state['pending']; name = pending['name']
            if name not in assets: fail('original upload remains unresolved; do not repeat it')
            row = _row(stage, assets[name], name, {key: pending[key] for key in ('sha256', 'size')})
            if row['id'] in pending['known_ids']: fail('pending upload reused an existing asset ID')
            state['uploaded'][name] = row; state['pending'] = None
            atomic_write(held / STATE, stage._canonical(state))
        files = dict(planned['files'])
        # Payloads are complete before the descriptor is built/uploaded. It has
        # no self-reference and uses immutable IDs, not names or latest assets.
        for name in [*sorted(files), MANIFEST]:
            if name == MANIFEST:
                raw = stage._canonical(_manifest(planned, state['uploaded']))
                files[name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw)}
                if (held / name).exists():
                    if regular_bytes(held / name, kit.MAX_METADATA) != raw: fail('local manifest changed')
                else: atomic_write(held / name, raw)
            if name in state['uploaded']:
                if {key: state['uploaded'][name][key] for key in ('sha256', 'size')} != files[name]: fail('completed manifest changed')
                continue
            assets = _remote_state(stage, planned, state, token)
            state['pending'] = {'name': name, **files[name], 'known_ids': sorted(row['id'] for row in state['uploaded'].values())}
            atomic_write(held / STATE, stage._canonical(state))
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
            try:
                before = os.fstat(fd)
                if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.geteuid()
                        or before.st_mode & 0o022 or not 0 < before.st_size < 2 * 1024**3): fail('upload file authority changed')
                digest, size = kit._hash(fd, kit.MAX_ASSET)
                if {'sha256': digest, 'size': size} != files[name]: fail('upload input changed')
                os.lseek(fd, 0, os.SEEK_SET)
                reply = _post(gh, planned['draft']['id'], name, fd)
                after = os.fstat(fd); named = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                def identity(info):
                    return (*kit._identity(info), info.st_uid, info.st_gid, info.st_mode, info.st_nlink)
                if identity(before) != identity(after) or identity(before) != identity(named): fail('upload input changed during POST')
            finally: os.close(fd)
            reply_row = _row(stage, reply, name, files[name])
            assets = _remote_state(stage, planned, state, token)
            row = _row(stage, assets.get(name), name, files[name])
            if row != reply_row or row['id'] in state['pending']['known_ids']: fail('upload response and independent readback differ')
            state['uploaded'][name] = row; state['pending'] = None
            atomic_write(held / STATE, stage._canonical(state))
        _remote_state(stage, planned, state, token)
        return {'draft_release_id': planned['draft']['id'], 'manifest_asset_id': state['uploaded'][MANIFEST]['id'],
                'manifest_sha256': state['uploaded'][MANIFEST]['sha256'], 'authenticated': False, 'published': False}


def _download_asset(stage, asset_id, destination, expected, token):
    endpoint = 'https://api.github.com/repos/' + stage.REPOSITORY + '/releases/assets/' + str(stage._positive(asset_id))
    with stage._request(endpoint, token, accept='application/octet-stream') as response:
        if response.status == 200:
            with destination.open('xb') as output:
                actual = stage._stream(response, output, expected['size'], time.monotonic() + 900)
        elif response.status == 302:
            location = response.headers.get('Location', '')
            parsed = urllib.parse.urlsplit(location)
            if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
                    or parsed.password is not None or parsed.port not in (None, 443) or parsed.fragment):
                fail('intake download redirect is not HTTPS')
            with stage._request(location) as body, destination.open('xb') as output:
                if body.status != 200: fail('unexpected intake download response')
                actual = stage._stream(body, output, expected['size'], time.monotonic() + 900)
        else: fail('unexpected intake asset response')
    if actual != expected: fail('received intake bytes differ from the independent selection')


def prepare(*, draft_release_id, manifest_asset_id, manifest_sha256, evidence_sha256, review_sha256,
            repository, tag, commit, profile, keyring, keyring_sha256, pip_sdist_sha256,
            run_id, run_attempt, ref, confirmation, output_dir, token=None):
    """Read-only hosted intake to ordinary unsigned preparation, never signing."""
    stage = helper('release-stage.py')
    if ref != 'refs/tags/' + tag or confirmation != 'prepare prebuilt intake ' + tag + ' ' + kit._sha(manifest_sha256):
        fail('exact tag and manifest preparation confirmation required')
    stage.selection(tag, commit, run_id, run_attempt, manifest_asset_id, manifest_sha256)
    if profile not in kit.PROFILES: fail('select a prebuilt profile')
    pins = {'debian_keyring_sha256': kit._sha(keyring_sha256), 'pip_sdist_sha256': kit._sha(pip_sdist_sha256)}
    kit._sha(evidence_sha256); kit._sha(review_sha256)
    stage._current_tag({'tag': tag, 'commit': commit}, token)
    draft = _draft(stage, draft_release_id, tag, commit, evidence_sha256, token)
    assets = _assets(stage, draft_release_id, token)
    selected_manifest = assets.get(MANIFEST)
    if (not isinstance(selected_manifest, dict) or selected_manifest.get('id') != manifest_asset_id
            or type(selected_manifest.get('size')) is not int or not 0 < selected_manifest['size'] <= kit.MAX_METADATA):
        fail('selected intake manifest is not in the exact draft')
    manifest_row = _row(stage, selected_manifest, MANIFEST,
        {'sha256': manifest_sha256, 'size': selected_manifest['size']})
    with tempfile.TemporaryDirectory(prefix='.iris-hosted-intake-', dir=kit._path(output_dir).parent) as temporary:
        work = Path(temporary); raw_manifest = work / MANIFEST
        _download_asset(stage, manifest_asset_id, raw_manifest,
            {key: manifest_row[key] for key in ('sha256', 'size')}, token)
        intake = kit._json(regular_bytes(raw_manifest, kit.MAX_METADATA))
        kit._keys(intake, INTAKE_FIELDS)
        expected = {'schema': SCHEMA, 'repository': stage.REPOSITORY, 'tag': tag, 'commit': commit,
            'profile': profile, 'draft': draft, 'candidate_evidence_sha256': evidence_sha256,
            'source_review_sha256': review_sha256, 'external_pins': pins}
        if {key: intake[key] for key in expected} != expected: fail('intake differs from independent selections')
        records = intake['files']
        if not isinstance(records, dict): fail('intake file map is invalid')
        rows = {}; ids = {manifest_asset_id}
        for name, row in records.items():
            kit._keys(row, {'id', 'sha256', 'size'}); kit._name(name)
            asset_id = stage._positive(row['id'])
            if asset_id in ids or name == MANIFEST: fail('intake manifest aliases assets or itself')
            ids.add(asset_id); rows[name] = {key: row[key] for key in ('sha256', 'size')}
            if _row(stage, assets.get(name), name, rows[name]) != row: fail('intake asset association changed')
        _limits(rows)
        if set(assets) != {*rows, MANIFEST}: fail('dedicated draft contains extra or missing assets')
        if (rows.get(gate.completion.MANIFEST, {}).get('sha256') != evidence_sha256
                or rows.get(gate.REVIEW_NAME, {}).get('sha256') != review_sha256): fail('selected candidate or review missing')
        completed = work / 'completed'; completed.mkdir(mode=0o700)
        review = work / gate.REVIEW_NAME
        for name, row in rows.items():
            _download_asset(stage, records[name]['id'], review if name == gate.REVIEW_NAME else completed / name, row, token)
        independent_keyring = work / 'keyring.gpg'
        if kit._snapshot(kit._path(keyring), independent_keyring, kit.MAX_METADATA) != keyring_sha256: fail('independent keyring changed')
        record = work / gate.STAGE_NAME
        stage.create_stage_record(record, tag, commit, run_id, run_attempt)
        prepared = work / 'prepared'
        gate.prepare_prebuilt(completed, evidence_sha256, prepared, repository=repository, tag=tag, commit=commit,
            debian_keyring=independent_keyring, pip_sdist_sha256=pip_sdist_sha256,
            source_review=review, expected_review_sha256=review_sha256,
            stage_record=record, expected_stage_sha256=hashlib.sha256(regular_bytes(record)).hexdigest())
        final_assets = _assets(stage, draft_release_id, token)
        if set(final_assets) != set(assets): fail('draft asset set changed during preparation')
        for name, row in {**records, MANIFEST: manifest_row}.items():
            if _row(stage, final_assets[name], name, {key: row[key] for key in ('sha256', 'size')}) != row:
                fail('intake changed during source validation')
        if _draft(stage, draft_release_id, tag, commit, evidence_sha256, token) != draft: fail('draft changed')
        stage._current_tag(expected, token)
        with gate._publication(output_dir) as (sealed, _):
            files = {}
            for path in sorted(prepared.iterdir()):
                row = gate.completion._file(path); files[path.name] = row
                if kit._snapshot(path, sealed / path.name, kit.MAX_ASSET) != row['sha256']:
                    fail('prepared output changed before export')
            if helper('hosted-prebuilt-stage.py')._inventory(sealed) != files:
                fail('unsigned preparation changed during export')
    return {'draft_release_id': draft_release_id, 'manifest_asset_id': manifest_asset_id,
            'manifest_sha256': manifest_sha256, 'run_id': run_id, 'run_attempt': run_attempt,
            'authenticated': False, 'published': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest='command', required=True)
    local = commands.add_parser('plan', allow_abbrev=False)
    for name in ('completed-dir', 'source-review', 'debian-keyring', 'repository', 'output-dir'):
        local.add_argument('--' + name, type=Path, required=True)
    hosted = commands.add_parser('prepare', allow_abbrev=False)
    for name in ('repository', 'keyring', 'output-dir'): hosted.add_argument('--' + name, type=Path, required=True)
    for command in (local, hosted):
        for name in ('tag', 'commit', 'profile', 'evidence-sha256', 'review-sha256', 'keyring-sha256', 'pip-sdist-sha256'):
            command.add_argument('--' + name, required=True)
        command.add_argument('--draft-release-id', type=int, required=True)
    for name in ('manifest-asset-id', 'run-id', 'run-attempt'): hosted.add_argument('--' + name, type=int, required=True)
    for name in ('manifest-sha256', 'ref', 'confirmation'): hosted.add_argument('--' + name, required=True)
    transfer = commands.add_parser('upload', allow_abbrev=False)
    transfer.add_argument('--state-dir', type=Path, required=True)
    transfer.add_argument('--github-cli', type=Path, default=Path('/usr/bin/gh'))
    transfer.add_argument('--plan-sha256', required=True); transfer.add_argument('--confirmation', required=True)
    args = vars(parser.parse_args(argv)); command = args.pop('command'); token = os.environ.get('GH_TOKEN')
    try:
        if command == 'plan':
            args['directory'] = args.pop('completed_dir'); result = plan(**args, token=token)
        elif command == 'upload':
            args['directory'] = args.pop('state_dir'); result = upload(**args, token=token)
        else: result = prepare(**args, token=token)
        print(json.dumps(result, sort_keys=True)); return 0
    except (InstallError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('Prebuilt intake refused. Preserve the plan and pending upload; no automatic retry, deletion or publication.')
        return 1


if __name__ == '__main__': raise SystemExit(main())
