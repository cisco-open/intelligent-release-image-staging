# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Actual intake writers/intent recovery; GitHub and positive crypto are modeled."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from iris_installer import prebuilt_release as gate, release_kit as kit
from iris_installer.state import InstallError
from test_release_stage import (stage, prebuilt, STAGE, TAG, COMMIT, sha, packed, replace_files)
from test_hosted_prebuilt_stage import incoming, modeled_validator, subject as HOSTED

spec = importlib.util.spec_from_file_location('prebuilt_intake_subject', ROOT / 'tools/prebuilt-intake.py')
subject = importlib.util.module_from_spec(spec); spec.loader.exec_module(subject)
REAL_VALIDATOR = gate.check_completed_candidate


@pytest.fixture
def intake(incoming, tmp_path, monkeypatch):
    prepared, selected, options = incoming
    original = dict(prepared['files'])
    validations = modeled_validator(monkeypatch, original)
    directory = tmp_path / 'completed'; directory.mkdir(mode=0o700)
    evidence = json.loads(original[gate.completion.MANIFEST])
    for name in {*evidence['files'], gate.completion.MANIFEST}:
        (directory / name).write_bytes(original[name])
    review = tmp_path / 'review.json'; review.write_bytes(original[gate.REVIEW_NAME])
    old_api = STAGE._api
    draft = {'id': 73, 'draft': True, 'published_at': None, 'target_commitish': COMMIT,
             'tag_name': 'iris-prebuilt-intake-' + selected['candidate_evidence_sha256'][:16]}
    value = {'prepared': prepared, 'selected': selected, 'original': original, 'validations': validations,
             'draft': draft, 'assets': {}, 'bytes': {}, 'posts': [], 'unknown': None}
    def api(endpoint, token):
        if endpoint == '/releases/73': return dict(value['draft'])
        if endpoint == '/releases/73/assets?per_page=100': return copy.deepcopy(list(value['assets'].values()))
        return old_api(endpoint, token)
    monkeypatch.setattr(STAGE, '_api', api)
    monkeypatch.setattr(subject, 'helper', lambda name: STAGE if name == 'release-stage.py' else HOSTED)
    monkeypatch.setattr(kit, '_verifier', lambda path, root: (path, '0' * 64))
    def post(gh, release_id, name, descriptor):
        assert release_id == 73
        state = json.loads((value['output'] / subject.STATE).read_bytes())
        assert state['pending']['name'] == name  # Durable intent exists before any POST.
        assert name not in value['assets']
        raw = os.read(descriptor, 1024**2)
        row = {'id': 1000 + len(value['assets']), 'name': name, 'state': 'uploaded',
               'size': len(raw), 'digest': 'sha256:' + sha(raw)}
        value['posts'].append(name); value['assets'][name] = row; value['bytes'][row['id']] = raw
        if value['unknown'] == name: raise OSError('synthetic private canary; accepted response lost')
        return dict(row)
    monkeypatch.setattr(subject, '_post', post)
    def download(stage, asset_id, destination, expected, token):
        raw = value['bytes'][asset_id]
        assert {'sha256': sha(raw), 'size': len(raw)} == expected
        with destination.open('xb') as stream: stream.write(raw)
    monkeypatch.setattr(subject, '_download_asset', download)
    value['output'] = tmp_path / 'upload-plan'
    value['plan_options'] = {'directory': directory, 'evidence_sha256': selected['candidate_evidence_sha256'],
        'output_dir': value['output'], 'repository': options['repository'], 'tag': TAG, 'commit': COMMIT,
        'profile': prepared['profile'], 'source_review': review, 'review_sha256': selected['source_review_sha256'],
        'debian_keyring': options['keyring'], 'keyring_sha256': selected['external_pins']['debian_keyring_sha256'],
        'pip_sdist_sha256': selected['external_pins']['pip_sdist_sha256'], 'draft_release_id': 73}
    value['hosted_options'] = {'draft_release_id': 73, 'repository': options['repository'], 'tag': TAG, 'commit': COMMIT,
        'profile': prepared['profile'], 'evidence_sha256': selected['candidate_evidence_sha256'],
        'review_sha256': selected['source_review_sha256'], 'keyring': options['keyring'],
        'keyring_sha256': selected['external_pins']['debian_keyring_sha256'], 'pip_sdist_sha256': 'c' * 64,
        'run_id': 91, 'run_attempt': 2, 'ref': 'refs/tags/' + TAG, 'output_dir': tmp_path / 'unsigned-intake'}
    return value


def local_plan(value):
    result = subject.plan(**value['plan_options'])
    value['plan_sha256'] = result['plan_sha256']
    return result


def transfer(value):
    return subject.upload(value['output'], value['plan_sha256'], github_cli=Path('/independent/gh'),
        confirmation='upload prebuilt intake ' + value['plan_sha256'])


def hosted(value, transferred):
    options = {**value['hosted_options'], 'manifest_asset_id': transferred['manifest_asset_id'],
        'manifest_sha256': transferred['manifest_sha256'],
        'confirmation': 'prepare prebuilt intake ' + TAG + ' ' + transferred['manifest_sha256']}
    return subject.prepare(**options)


def test_actual_plan_upload_prepare_and_consumer_preserve_both_profiles(intake):
    value = intake; local_plan(value)
    assert len(value['validations']) == 1
    assert value['posts'] == []
    transferred = transfer(value)
    assert value['posts'][-1] == subject.MANIFEST and value['posts'].count(subject.MANIFEST) == 1
    manifest = json.loads(value['bytes'][transferred['manifest_asset_id']])
    assert subject.MANIFEST not in manifest['files']
    assert set(manifest['files']) == set(json.loads((value['output'] / subject.PLAN).read_bytes())['files'])
    hosted(value, transferred)
    assert len(value['validations']) == 2
    unsigned = value['hosted_options']['output_dir']
    files = {path.name: path.read_bytes() for path in unsigned.iterdir()}
    for name in manifest['files']:
        assert files[name] == value['bytes'][manifest['files'][name]['id']]
    assert json.loads(files[gate.STAGE_NAME])['run_id'] == 91
    prepared = value['prepared']; prepared['selected'] = STAGE.selection(TAG, COMMIT, 91, 2, 95, sha(packed(files)))
    prepared['run'].update(id=91, run_attempt=2, event='workflow_dispatch',
        path='.github/workflows/prepare-prebuilt.yml@refs/tags/' + TAG, head_branch=TAG)
    prepared['artifact'].update(id=95, name='iris-prebuilt-unsigned-91-2',
        workflow_run={'id': 91, 'repository_id': 91, 'head_repository_id': 91, 'head_sha': COMMIT})
    replace_files(prepared, files)
    selected = HOSTED.selection(tag=TAG, commit=COMMIT, profile=prepared['profile'], run_id=91, run_attempt=2,
        artifact_id=95, artifact_sha256=sha(prepared['archive']), evidence_sha256=value['selected']['candidate_evidence_sha256'],
        review_sha256=value['selected']['source_review_sha256'], keyring_sha256=value['plan_options']['keyring_sha256'], pip_sdist_sha256='c' * 64)
    output = HOSTED.prepare(selected, repository=value['plan_options']['repository'], output_dir=unsigned.parent / 'authentication-input',
        keyring=value['hosted_options']['keyring'], current_run_id=101, current_run_attempt=1,
        ref='refs/tags/' + TAG, confirmation='authenticate ' + TAG + ' ' + selected['candidate_evidence_sha256'])
    assert len(value['validations']) == 3
    assert json.loads((output / gate.STAGE_NAME).read_bytes())['run_id'] == 101
    assert (output / gate.REVIEW_NAME).read_bytes() == value['original'][gate.REVIEW_NAME]
    for name in manifest['files']:
        assert (output / name).read_bytes() == value['bytes'][manifest['files'][name]['id']]
    before = list(value['posts']); assert transfer(value) == transferred
    assert value['posts'] == before  # Completed upload is reconciled, never repeated.


@pytest.mark.parametrize('unknown', ['payload', 'manifest'])
def test_accepted_unknown_upload_reconciles_exact_original_without_reposting(intake, unknown):
    value = intake; local_plan(value)
    files = json.loads((value['output'] / subject.PLAN).read_bytes())['files']
    selected = min(files) if unknown == 'payload' else subject.MANIFEST
    value['unknown'] = selected
    with pytest.raises(OSError): transfer(value)
    assert json.loads((value['output'] / subject.STATE).read_bytes())['pending']['name'] == selected
    before = list(value['posts']); value['unknown'] = None
    result = transfer(value)
    assert value['posts'].count(selected) == 1
    assert value['posts'][:len(before)] == before
    assert result['authenticated'] is result['published'] is False


def test_unknown_without_visible_asset_stays_pending_and_never_reposts(intake):
    value = intake; local_plan(value)
    name = min(json.loads((value['output'] / subject.PLAN).read_bytes())['files'])
    value['unknown'] = name
    with pytest.raises(OSError): transfer(value)
    del value['assets'][name]
    before = list(value['posts'])
    with pytest.raises(InstallError, match='remains unresolved'): transfer(value)
    assert value['posts'] == before


@pytest.mark.parametrize('fault', ['inert', 'directory', 'symlink', 'hardlink', 'writable', 'foreign-name'])
def test_atomic_scratch_is_non_authority_and_only_exact_private_leaves_are_ignored(intake, fault):
    value = intake; local_plan(value)
    name = min(json.loads((value['output'] / subject.PLAN).read_bytes())['files'])
    value['unknown'] = name
    with pytest.raises(OSError): transfer(value)
    scratch = value['output'] / ('.iris-abcdefgh' if fault != 'foreign-name' else 'unknown-file')
    if fault == 'directory': scratch.mkdir()
    elif fault == 'symlink': scratch.symlink_to(value['output'] / subject.PLAN)
    else:
        scratch.write_bytes(b'inert uncommitted state, never parsed'); scratch.chmod(0o600)
        if fault == 'hardlink': os.link(scratch, value['output'].parent / 'scratch-alias')
        if fault == 'writable': scratch.chmod(0o620)
    before = list(value['posts']); value['unknown'] = None
    if fault == 'inert':
        transfer(value)
        assert scratch.read_bytes() == b'inert uncommitted state, never parsed'
    else:
        with pytest.raises(InstallError, match='untracked files'): transfer(value)
        assert value['posts'] == before
    assert value['posts'].count(name) == 1


@pytest.mark.parametrize('failure', ['launch', 'timeout', 'malformed-response'])
def test_pending_intent_survives_every_uncertain_post_failure(intake, monkeypatch, failure):
    value = intake; local_plan(value)
    first = min(json.loads((value['output'] / subject.PLAN).read_bytes())['files'])
    real_post = subject._post
    def failed(*args):
        if failure == 'launch': raise FileNotFoundError('private transport canary')
        if failure == 'timeout':
            real_post(*args)
            raise subprocess.TimeoutExpired('inert invocation', 900)
        real_post(*args)
        return {'unrecognized': 'private response canary'}
    monkeypatch.setattr(subject, '_post', failed)
    with pytest.raises((InstallError, OSError, subprocess.SubprocessError)): transfer(value)
    pending = json.loads((value['output'] / subject.STATE).read_bytes())['pending']
    assert pending['name'] == first
    before = list(value['posts']); monkeypatch.setattr(subject, '_post', real_post)
    if failure == 'launch':
        with pytest.raises(InstallError, match='remains unresolved'): transfer(value)
    else: transfer(value)
    assert value['posts'].count(first) <= 1
    assert value['posts'][:len(before)] == before


@pytest.mark.parametrize('boundary', ['local-plan', 'hosted-prepare'])
def test_real_complete_validator_is_mandatory_before_any_unsigned_export(intake, monkeypatch, boundary):
    value = intake
    if boundary == 'hosted-prepare':
        local_plan(value); transferred = transfer(value); before = list(value['posts'])
    else: before = []
    monkeypatch.setattr(gate, 'check_completed_candidate', REAL_VALIDATOR)
    with pytest.raises(InstallError):
        if boundary == 'local-plan': local_plan(value)
        else: hosted(value, transferred)
    path = value['output'] if boundary == 'local-plan' else value['hosted_options']['output_dir']
    assert not path.exists() and value['posts'] == before


@pytest.mark.parametrize('fault', ['missing-state', 'state-symlink', 'changed-source', 'foreign', 'replaced', 'wrong-confirmation', 'cloned-plan'])
def test_intake_never_overwrites_adopts_or_replays_unproved_state(intake, fault):
    value = intake; local_plan(value)
    plan = json.loads((value['output'] / subject.PLAN).read_bytes())
    if fault in ('missing-state', 'state-symlink'):
        (value['output'] / subject.STATE).unlink()
        if fault == 'state-symlink': (value['output'] / subject.STATE).symlink_to(value['output'] / 'absent')
    elif fault == 'changed-source':
        path = value['output'] / min(plan['files']); path.chmod(0o600); path.write_bytes(b'changed')
    elif fault == 'foreign':
        value['assets']['foreign.bin'] = {'id': 900, 'name': 'foreign.bin'}
    elif fault == 'replaced':
        transfer(value)
        value['assets'][min(plan['files'])]['id'] += 100
    elif fault == 'cloned-plan':
        clone = value['output'].with_name('copied-intake')
        shutil.copytree(value['output'], clone); value['output'] = clone
    before = list(value['posts'])
    with pytest.raises((InstallError, OSError)):
        if fault == 'wrong-confirmation':
            subject.upload(value['output'], value['plan_sha256'], github_cli=Path('/independent/gh'), confirmation='upload everything')
        else: transfer(value)
    assert value['posts'] == before


@pytest.mark.parametrize('field,value', [('draft', False), ('target_commitish', 'main'), ('tag_name', TAG), ('id', True)])
def test_only_existing_dedicated_draft_is_eligible_no_final_release_mutation(intake, field, value):
    intake['draft'][field] = value
    with pytest.raises(InstallError): local_plan(intake)
    assert intake['posts'] == [] and not intake['output'].exists()


@pytest.mark.parametrize('which', ['evidence', 'review', 'keyring', 'pip'])
def test_independent_roots_and_review_cannot_be_reselected_from_intake(intake, which):
    key = {'evidence': 'evidence_sha256', 'review': 'review_sha256', 'keyring': 'keyring_sha256', 'pip': 'pip_sdist_sha256'}[which]
    intake['plan_options'][key] = '0' * 64
    with pytest.raises(InstallError): local_plan(intake)
    assert not intake['output'].exists() and intake['posts'] == []


@pytest.mark.parametrize('fault', ['branch', 'keyring', 'review', 'id', 'foreign', 'bytes', 'self-reference'])
def test_hosted_read_only_prepare_refuses_selection_or_closed_input_drift(intake, fault):
    value = intake; local_plan(value); result = transfer(value)
    options = {**value['hosted_options'], 'manifest_asset_id': result['manifest_asset_id'], 'manifest_sha256': result['manifest_sha256'],
        'confirmation': 'prepare prebuilt intake ' + TAG + ' ' + result['manifest_sha256']}
    if fault == 'branch': options['ref'] = 'refs/heads/' + TAG
    elif fault in ('keyring', 'review'): options[fault + '_sha256'] = '0' * 64
    elif fault == 'id': options['manifest_asset_id'] += 1
    elif fault == 'foreign': value['assets']['foreign.bin'] = {'id': 900, 'name': 'foreign.bin'}
    elif fault == 'bytes':
        row = value['assets'][min(json.loads((value['output'] / subject.PLAN).read_bytes())['files'])]; row['digest'] = 'sha256:' + '0' * 64
    elif fault == 'self-reference':
        raw = value['bytes'][result['manifest_asset_id']]; manifest = json.loads(raw)
        manifest['files'][subject.MANIFEST] = {'id': result['manifest_asset_id'], 'sha256': sha(raw), 'size': len(raw)}
        raw = STAGE._canonical(manifest); value['bytes'][result['manifest_asset_id']] = raw
        value['assets'][subject.MANIFEST].update(digest='sha256:' + sha(raw), size=len(raw))
        options.update(manifest_sha256=sha(raw), confirmation='prepare prebuilt intake ' + TAG + ' ' + sha(raw))
    before = list(value['posts'])
    with pytest.raises((InstallError, AssertionError)): subject.prepare(**options)
    assert not options['output_dir'].exists() and value['posts'] == before


def test_release_bounds_are_strict_and_manifest_has_no_self_reference():
    with pytest.raises(InstallError): subject._limits({'large.bin': {'sha256': 'a' * 64, 'size': 2 * 1024**3}})
    with pytest.raises(InstallError): subject._limits({f'{i}.bin': {'sha256': 'a' * 64, 'size': 1} for i in range(65)})


@pytest.mark.parametrize('redirect', [False, True])
def test_binary_intake_download_handles_200_or_302_without_forwarded_token(tmp_path, monkeypatch, redirect):
    raw = b'exact public intake asset'; calls = []
    class Response(io.BytesIO):
        def __init__(self, status, data=b'', headers=None): super().__init__(data); self.status = status; self.headers = headers or {}
        def read1(self, size): return self.read(size)
    def request(url, token=None, **kwargs):
        calls.append((url, token, kwargs))
        if len(calls) == 1 and redirect: return Response(302, headers={'Location': 'https://github-storage.example/exact'})
        return Response(200, raw)
    monkeypatch.setattr(STAGE, '_request', request)
    subject._download_asset(STAGE, 99, tmp_path / 'asset', {'sha256': sha(raw), 'size': len(raw)}, 'private-token-canary')
    assert calls[0][0] == 'https://api.github.com/repos/' + STAGE.REPOSITORY + '/releases/assets/99'
    assert calls[0][2]['accept'] == 'application/octet-stream'
    if redirect: assert calls[1][1] is None


def test_upload_transport_uses_only_fixed_endpoint_and_inherited_input_fd(tmp_path, monkeypatch):
    source = tmp_path / 'public-input'; source.write_bytes(b'exact public bytes')
    calls = []
    monkeypatch.setenv('GH_TOKEN', 'private-token-canary')
    monkeypatch.setattr(subject, 'helper', lambda name: STAGE)
    def run(command, **options):
        calls.append(command)
        assert 'private-token-canary' not in ' '.join(command)
        assert str(source) not in command
        assert command[command.index('POST') + 1].startswith('https://uploads.github.com/repos/' + STAGE.REPOSITORY + '/releases/73/assets?name=')
        descriptor = options['pass_fds'][0]
        assert os.read(descriptor, 4096) == b'exact public bytes'
        assert options['timeout'] == 900 and options['stderr'] == subprocess.DEVNULL
        assert options['env']['GH_HOST'] == 'github.com'
        assert options['env']['GH_TOKEN'] == 'private-token-canary'
        options['stdout'].write(STAGE._canonical({'id': 2, 'name': 'asset+input.bin'}))
    monkeypatch.setattr(subject.subprocess, 'run', run)
    fd = os.open(source, os.O_RDONLY)
    try:
        assert subject._post(Path('/trusted/gh'), 73, 'asset+input.bin', fd)['id'] == 2
    finally: os.close(fd)
    assert len(calls) == 1 and 'asset%2Binput.bin' in calls[0][6]


@pytest.mark.parametrize('command', ['plan', 'upload', 'prepare'])
def test_cli_forwards_only_environment_token_and_never_prints_it(tmp_path, monkeypatch, capsys, command):
    token = 'private-environment-token-canary'; calls = []
    monkeypatch.setenv('GH_TOKEN', token)
    def operation(**kwargs):
        calls.append(kwargs)
        assert kwargs['token'] == token
        return {'scope': 'modeled CLI boundary only'}
    monkeypatch.setattr(subject, command, operation)
    if command == 'upload':
        argv = [command, '--state-dir', str(tmp_path), '--plan-sha256', 'a' * 64,
                '--confirmation', 'upload prebuilt intake ' + 'a' * 64]
    else:
        argv = [command, '--repository', str(tmp_path), '--output-dir', str(tmp_path / 'new'),
            '--tag', TAG, '--commit', COMMIT, '--profile', 'prepared-host', '--draft-release-id', '73',
            '--evidence-sha256', 'a' * 64, '--review-sha256', 'b' * 64,
            '--keyring-sha256', 'c' * 64, '--pip-sdist-sha256', 'd' * 64]
        if command == 'plan': argv += ['--completed-dir', str(tmp_path), '--source-review', str(tmp_path / 'review'),
                                      '--debian-keyring', str(tmp_path / 'keyring')]
        else: argv += ['--keyring', str(tmp_path / 'keyring'), '--manifest-asset-id', '99', '--manifest-sha256', 'e' * 64,
                       '--run-id', '101', '--run-attempt', '1', '--ref', 'refs/tags/' + TAG,
                       '--confirmation', 'prepare prebuilt intake ' + TAG + ' ' + 'e' * 64]
    assert token not in ' '.join(argv)
    assert subject.main(argv) == 0 and len(calls) == 1
    assert token not in capsys.readouterr().out


def test_read_only_intake_workflow_has_no_authentication_or_publication_permissions():
    workflow = yaml.load((ROOT / '.github/workflows/prepare-prebuilt.yml').read_text(), Loader=yaml.BaseLoader)
    assert set(workflow['on']) == {'workflow_dispatch'}
    job = workflow['jobs']['prepare']
    assert job['permissions'] == {'contents': 'read'}
    assert "startsWith(github.ref, 'refs/tags/v20')" in job['if']
    assert not any('attest' in step.get('uses', '') for step in job['steps'])
    actual = next(step['run'] for step in job['steps'] if 'prebuilt-intake.py prepare' in step.get('run', ''))
    assert '${{ inputs.' not in actual
    assert '--manifest-sha256 "$MANIFEST_SHA256"' in actual
    assert not any('gh release create' in step.get('run', '') or 'gh release upload' in step.get('run', '') for step in job['steps'])
