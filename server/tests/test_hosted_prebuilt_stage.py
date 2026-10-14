# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Local hosted-route composition; never signing, publication or qualification.

Existing producer and metadata joins execute. Positive transport fixtures model
the expensive source validator explicitly; a separate negative uses its real
implementation. The existing validator suites cover its source/crypto contracts.
"""
from contextlib import contextmanager
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from iris_installer import prebuilt_release as gate
from iris_installer.state import InstallError
from test_release_stage import (stage, prebuilt, STAGE, TAG, COMMIT, sha, inventory,
                                packed, prebuilt_qualification, rebind_prebuilt, replace_files)

spec = importlib.util.spec_from_file_location('hosted_prebuilt_subject', ROOT / 'tools/hosted-prebuilt-stage.py')
subject = importlib.util.module_from_spec(spec); spec.loader.exec_module(subject)


@pytest.fixture
def incoming(prebuilt, tmp_path, monkeypatch):
    """Actual unsigned gate bytes, mocked GitHub GET, independent selected pins."""
    files = dict(prebuilt['files'])
    keyring = tmp_path / 'independently-selected-keyring.gpg'
    keyring.write_bytes(b'public keyring fixture; not an actual trust approval')
    keyring.chmod(0o600)
    evidence = json.loads(files[gate.completion.MANIFEST])
    evidence['external_pins']['debian_keyring_sha256'] = sha(keyring.read_bytes())
    files[gate.completion.MANIFEST] = STAGE._canonical(evidence)
    rebind_prebuilt(prebuilt, files)
    files = {name: raw for name, raw in prebuilt['files'].items()
             if name not in ('attestations.jsonl', 'prebuilt-incoming.json', 'release.json', 'SHA256SUMS')}
    files['release.json'] = STAGE._canonical({'schema': 1, 'repository': STAGE.REPOSITORY,
        'workflow': STAGE.WORKFLOW, 'tag': TAG, 'commit': COMMIT, 'assets': inventory(files)})
    files['SHA256SUMS'] = ''.join(sha(files[name]) + '  ' + name + '\n' for name in sorted(files)).encode()
    replace_files(prebuilt, files)
    prebuilt['artifact']['name'] = 'unsigned-reviewed-fixture'
    prebuilt['run']['path'] = '.github/workflows/preparation.yml'
    monkeypatch.setattr(subject, 'stage_helper', lambda: STAGE)
    monkeypatch.setattr(gate, '_git_selection', lambda *args: {})
    selected = subject.selection(tag=TAG, commit=COMMIT, profile=prebuilt['profile'],
        run_id=31, run_attempt=2, artifact_id=47, artifact_sha256=sha(prebuilt['archive']),
        evidence_sha256=sha(files[gate.completion.MANIFEST]), review_sha256=sha(files[gate.REVIEW_NAME]),
        keyring_sha256=sha(keyring.read_bytes()), pip_sdist_sha256='c' * 64)
    options = {'repository': tmp_path / 'trusted-repository', 'output_dir': tmp_path / 'hosted-output',
        'keyring': keyring, 'current_run_id': 51, 'current_run_attempt': 3, 'ref': 'refs/tags/' + TAG,
        'confirmation': 'authenticate ' + TAG + ' ' + selected['candidate_evidence_sha256'],
        'token': 'inert-secret-canary'}
    return prebuilt, selected, options


def modeled_validator(monkeypatch, original):
    calls = []
    @contextmanager
    def validate(directory, digest, **options):
        evidence = json.loads(original[gate.completion.MANIFEST])
        preparation = json.loads(original[gate.PREPARATION_NAME])
        assert digest == sha(original[gate.completion.MANIFEST])
        assert hashlib.sha256(options['debian_keyring'].read_bytes()).hexdigest() == evidence['external_pins']['debian_keyring_sha256']
        assert options['pip_sdist_sha256'] == evidence['external_pins']['pip_sdist_sha256']
        assert (options['tag'], options['commit']) == (TAG, COMMIT)
        assert set(p.name for p in directory.iterdir()) == {*evidence['files'], gate.completion.MANIFEST}
        for name in preparation['delivery_assets']:
            (directory / name).write_bytes(original[name])
        calls.append(options)
        yield gate.CheckedCandidate(directory, evidence, digest, preparation['payload_assets'],
            gate._companions(evidence), preparation['git_source_parity'], preparation['delivery_assets'])
    monkeypatch.setattr(gate, 'check_completed_candidate', validate)
    return calls


def test_real_hosted_writer_preserves_review_payload_and_rebinds_only_current_run(incoming, monkeypatch):
    prebuilt, selected, options = incoming
    original = dict(prebuilt['files'])
    calls = modeled_validator(monkeypatch, original)
    output = subject.prepare(selected, **options)
    assert len(calls) == 1
    assert not (output / 'attestations.jsonl').exists()
    for name, row in json.loads(original[gate.completion.MANIFEST])['files'].items():
        assert (output / name).read_bytes() == original[name]
        assert sha((output / name).read_bytes()) == row['sha256']
    assert (output / gate.REVIEW_NAME).read_bytes() == original[gate.REVIEW_NAME]
    record = json.loads((output / gate.STAGE_NAME).read_bytes())
    assert (record['run_id'], record['run_attempt']) == (51, 3)
    receipt = json.loads((output / subject.RECEIPT).read_bytes())
    assert receipt['incoming']['artifact_id'] == 47
    assert receipt['incoming']['artifact_sha256'] == selected['artifact_sha256']
    assert receipt['incoming']['run_id'] == 31 and receipt['incoming']['run_attempt'] == 2
    assert receipt['external_pins'] == selected['external_pins']
    assert receipt['review_authority_verified'] is receipt['payloads_rebuilt'] is False
    files = {p.name: {'sha256': sha(p.read_bytes()), 'size': p.stat().st_size} for p in output.iterdir()}
    joined = STAGE._prebuilt_metadata(output, files,
        dict(prebuilt['selected'], run_id=51, run_attempt=3), prebuilt['profile'], unsigned=True)
    assert joined['prebuilt_inputs']['source_review_sha256'] == selected['source_review_sha256']


def test_actual_complete_validator_is_required_before_any_output_or_authentication(incoming, monkeypatch):
    prebuilt, selected, options = incoming
    # The inert fixture is not valid source or image material. Restore the real
    # complete validator: structural metadata alone must never authenticate it.
    monkeypatch.undo()
    monkeypatch.setattr(subject, 'stage_helper', lambda: STAGE)
    monkeypatch.setattr(gate, '_git_selection', lambda *args: {})
    original_api = lambda endpoint, token: (
        {'ref': 'refs/tags/' + TAG, 'object': {'type': 'commit', 'sha': COMMIT}}
        if endpoint.startswith('/git/ref/') else prebuilt['run'] if '/attempts/' in endpoint else prebuilt['artifact'])
    monkeypatch.setattr(STAGE, '_api', original_api)
    monkeypatch.setattr(STAGE, '_download', lambda selected, path, size, token: path.write_bytes(prebuilt['archive']))
    with pytest.raises(InstallError): subject.prepare(selected, **options)
    assert not options['output_dir'].exists()


def test_hosted_writer_to_actual_auth_inventory_acquire_and_publication_contract(incoming, monkeypatch):
    """Real writers/joins for both profiles; only network and crypto are modeled."""
    prebuilt, selected, options = incoming
    original = dict(prebuilt['files'])
    validations = modeled_validator(monkeypatch, original)
    output = subject.prepare(selected, **options)
    assert len(validations) == 1  # Existing complete candidate validator is mandatory.
    files = {path.name: path.read_bytes() for path in output.iterdir()}
    files['attestations.jsonl'] = b'modeled signatures only; not hosted release authentication\n'
    (output / 'attestations.jsonl').write_bytes(files['attestations.jsonl'])
    auth = STAGE.kit._auth()
    verified = []
    def modeled_signature(command, *, check):
        assert check is True
        verified.append(command)
    monkeypatch.setattr(auth, 'subprocess', SimpleNamespace(run=modeled_signature))
    auth.verify(output, TAG, COMMIT)  # Actual inventory/parser/checksums and verifier argv.
    assert {Path(command[3]).name for command in verified} == set(files) - {'attestations.jsonl'}
    for command in verified:
        assert command[command.index('--source-ref') + 1] == 'refs/tags/' + TAG
        assert command[command.index('--source-digest') + 1] == COMMIT
        assert '--deny-self-hosted-runners' in command
    prebuilt['selected'] = STAGE.selection(TAG, COMMIT, 51, 3, 63, sha(packed(files)))
    prebuilt['run'].update(id=51, run_attempt=3, event='workflow_dispatch',
        path='.github/workflows/release.yml@refs/tags/' + TAG, head_branch=TAG)
    prebuilt['artifact'].update(id=63, name='iris-authenticated-51-3',
        workflow_run={'id': 51, 'repository_id': 91, 'head_repository_id': 91, 'head_sha': COMMIT})
    replace_files(prebuilt, files)
    acquired = STAGE.acquire_stage(prebuilt['selected'], output.parent / 'acquired', profile=prebuilt['profile'])
    assert acquired['files'] == inventory(files)
    assert acquired['prebuilt_binding']['candidate_evidence_sha256'] == selected['candidate_evidence_sha256']
    qualification = STAGE._canonical(prebuilt_qualification(prebuilt))
    publication = STAGE.prepare_publication(prebuilt['selected'], output.parent / 'publication',
        qualification=qualification, qualification_sha256=sha(qualification),
        actor='dispatcher', actor_id=17, triggering_actor='reviewer',
        confirmation='publish ' + TAG + ' ' + sha(files['release.json']), profile=prebuilt['profile'])
    assert publication['files'] == inventory(files)
    assert publication['qualification_is_reviewer_statement'] is True
    assert publication['prebuilt_binding'] == acquired['prebuilt_binding']
    for name, raw in files.items():
        assert (output.parent / 'publication/assets' / name).read_bytes() == raw


def test_private_producer_fd_alias_is_not_admitted_as_a_public_input_path(tmp_path):
    output = tmp_path / 'publication'
    with gate._publication(output) as (held, _):
        with pytest.raises(InstallError, match='must not traverse symlinks'):
            STAGE.kit._path(held)
        subject._write_metadata(held, 'metadata.json', b'{"fixture":true}\n')
        assert subject._inventory(held) == {'metadata.json': {'sha256': sha(b'{"fixture":true}\n'), 'size': 17}}
    assert (output / 'metadata.json').read_bytes() == b'{"fixture":true}\n'


@pytest.mark.parametrize('fault', ['symlink', 'hardlink', 'writable', 'directory', 'changed-leaf', 'changed-directory'])
def test_held_staging_inventory_rejects_aliases_permissions_and_read_races(tmp_path, monkeypatch, fault):
    private = tmp_path / 'private'; private.mkdir(mode=0o700)
    leaf = private / 'asset.bin'; leaf.write_bytes(b'owned'); leaf.chmod(0o600)
    if fault == 'symlink':
        leaf.unlink(); leaf.symlink_to(tmp_path / 'untrusted')
    elif fault == 'hardlink':
        os.link(leaf, tmp_path / 'alias')
    elif fault == 'writable':
        leaf.chmod(0o620)
    elif fault == 'directory':
        leaf.unlink(); leaf.mkdir()
    elif fault.startswith('changed-'):
        original = STAGE.kit._hash
        def changed(*args, **kwargs):
            row = original(*args, **kwargs)
            if fault == 'changed-leaf':
                leaf.unlink(); leaf.write_bytes(b'other'); leaf.chmod(0o600)
            else: private.chmod(0o750)
            return row
        monkeypatch.setattr(STAGE.kit, '_hash', changed)
    with pytest.raises((InstallError, OSError)):
        subject._inventory(private)


@pytest.mark.parametrize('field,value', [
    ('ref', 'refs/heads/v2026.10.09'), ('ref', 'refs/tags/v2026.10.08'),
    ('confirmation', 'authenticate wrong candidate'), ('current_run_id', True)])
def test_caller_context_refuses_before_incoming_acquisition(incoming, field, value):
    prebuilt, selected, options = incoming
    options[field] = value; before = list(prebuilt['calls'])
    with pytest.raises(InstallError): subject.prepare(selected, **options)
    assert prebuilt['calls'] == before and not options['output_dir'].exists()


@pytest.mark.parametrize('change', ['review', 'evidence', 'keyring', 'pip', 'extra-selector'])
def test_independent_selections_cannot_come_from_self_reported_zip(incoming, change):
    prebuilt, selected, options = incoming
    selected = copy.deepcopy(selected)
    if change in ('review', 'evidence'):
        selected[{'review': 'source_review_sha256', 'evidence': 'candidate_evidence_sha256'}[change]] = '0' * 64
    elif change in ('keyring', 'pip'):
        selected['external_pins'][{'keyring': 'debian_keyring_sha256', 'pip': 'pip_sdist_sha256'}[change]] = '0' * 64
    else: selected['url'] = 'https://unselected.invalid/input.zip'
    with pytest.raises(InstallError): subject.prepare(selected, **options)
    assert not options['output_dir'].exists()


@pytest.mark.parametrize('which,field,value', [
    ('run', 'head_sha', '0' * 40), ('run', 'event', 'pull_request'), ('run', 'conclusion', 'failure'),
    ('run', 'run_attempt', 3), ('artifact', 'expired', True), ('artifact', 'digest', 'sha256:' + '0' * 64),
    ('artifact', 'name', '../../unselected'), ('artifact', 'size_in_bytes', True),
    ('artifact', 'workflow_run', {'id': 32, 'head_sha': COMMIT, 'repository_id': 91, 'head_repository_id': 91})])
def test_incoming_origin_is_fixed_repository_bound_not_an_arbitrary_download(incoming, which, field, value):
    prebuilt, selected, options = incoming
    prebuilt[which][field] = value
    with pytest.raises(InstallError): subject.prepare(selected, **options)
    assert not options['output_dir'].exists()


def test_actual_workflow_runs_validation_before_attestation_and_exports_without_publishing():
    workflow = yaml.load((ROOT / '.github/workflows/release.yml').read_text(), Loader=yaml.BaseLoader)
    assert set(workflow['on']) == {'push', 'workflow_dispatch'}
    inputs = workflow['on']['workflow_dispatch']['inputs']
    assert inputs['profile']['options'] == ['prepared-host', 'ubuntu-dependencies']
    job = workflow['jobs']['release']
    assert "startsWith(github.ref, 'refs/tags/v20')" in job['if']
    assert job['permissions']['contents'] == 'read' and job['permissions']['actions'] == 'read'
    steps = job['steps']; validation = next(i for i, s in enumerate(steps) if 'hosted-prebuilt-stage.py' in s.get('run', ''))
    attestation = next(i for i, s in enumerate(steps) if s.get('id') == 'attest')
    assert validation < attestation
    assert steps[validation]['if'] == "github.event_name == 'workflow_dispatch'"
    assert '${{ inputs.' not in steps[validation]['run']
    assert '--keyring-sha256 "$DEBIAN_KEYRING_SHA256"' in steps[validation]['run']
    assert '--pip-sdist-sha256 "$PIP_SDIST_SHA256"' in steps[validation]['run']
    assert not any('gh release create' in s.get('run', '') for s in steps)
