# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Local fixtures only: no builds, package installation, signing or network."""

from contextlib import contextmanager
from copy import deepcopy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import prebuilt_release as subject
from iris_installer.state import InstallError


TAG, COMMIT = 'v2026.10.09', 'a' * 40
encoded = subject.canonical
sha = subject._sha


def write(path, raw, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)


def tar(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(entries.items()):
            member = tarfile.TarInfo(name)
            member.mode, member.size = 0o644, len(raw)
            archive.addfile(member, io.BytesIO(raw))
    return gzip.compress(output.getvalue(), mtime=0)


def row(raw):
    return {'sha256': sha(raw), 'size': len(raw)}


@pytest.fixture
def gate(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    directory = tmp_path / 'completed'
    directory.mkdir(mode=0o700)
    source = {'VERSION': TAG[1:].encode() + b'\n', 'tools/release-auth.py': b'# retained helper; never run\n',
              'deliverables/aria2c-x86_64': b'client amd64', 'deliverables/aria2c-aarch64': b'client arm64'}
    source_rows = {name: sha(raw) for name, raw in source.items()}
    entries = {'iris/' + name: raw for name, raw in source.items()}
    entries['iris/artifacts/.gitkeep'] = b''
    manifest = ''.join(sha(raw) + '  ' + name + '\n' for name, raw in sorted(entries.items())).encode()
    entries['iris/MANIFEST.txt'] = manifest
    originals = {'iris.tgz': tar(entries), 'fixture.deb.source.json':
                 encoded({'schema': 1, 'commit': COMMIT, 'files': source_rows})}
    candidate = {'format': 'iris-local-release-candidate-v1', 'authenticated': False,
                 'tag': TAG, 'commit': COMMIT, 'version': TAG[1:], 'profile': 'prepared-host',
                 'files': {name: row(raw) for name, raw in originals.items()}}
    payload = {**originals, subject.completion.ORIGINAL: encoded(candidate)}
    proofs = {}
    for role in ('aria2', 'debian', 'alpine', 'core-python', 'runtime', 'image-notices'):
        name = 'aria2c-fixture-source.tar.gz' if role == 'aria2' else 'iris-' + role + '-sources.tar.gz'
        payload[name] = ('companion ' + role).encode()
        proofs[role] = {'asset': name, 'archive_sha256': sha(payload[name]), 'scope': role}
    proofs['aria2']['binary_sha256'] = {arch: sha(source['deliverables/aria2c-' + arch])
                                      for arch in ('x86_64', 'aarch64')}
    evidence = {'format': subject.completion.SCHEMA, 'authenticated': False, 'source_coverage_complete': False,
                'rebuild_verified': False, 'original_candidate_sha256': sha(encoded(candidate)),
                'tag': TAG, 'commit': COMMIT, 'profile': 'prepared-host', 'image_inventory_sha256': 'b' * 64,
                'source_agreement': {}, 'neutral_source_sha256': 'c' * 64, 'external_pins': {},
                'companions': proofs, 'files': {name: row(raw) for name, raw in payload.items()},
                'mechanical_evidence': 'fixture', 'remaining_gates': ['human review']}
    for name, raw in payload.items():
        write(directory / name, raw)
    def seal():
        write(directory / subject.completion.MANIFEST, encoded(evidence))
        return sha(encoded(evidence))
    tree = {name: {'mode': 0o644, 'blob': hashlib.sha1(
        b'blob ' + str(len(raw)).encode() + b'\0' + raw, usedforsecurity=False).hexdigest()}
        for name, raw in source.items()}
    monkeypatch.setattr(subject, '_git_selection', lambda *args: deepcopy(tree))
    calls = []
    def reconstruct(original, digest, output, **kwargs):
        calls.append(kwargs)
        assert original != directory
        assert sha((original / subject.completion.ORIGINAL).read_bytes()) == digest
        for role in proofs:
            key = 'image_notices' if role == 'image-notices' else role.replace('-', '_') + '_sources'
            assert kwargs[key].parent != directory
            assert sha(kwargs[key].read_bytes()) == proofs[role]['archive_sha256']
        assert kwargs['debian_keyring'] == tmp_path / 'keyring.gpg'
        assert kwargs['pip_sdist_sha256'] == 'd' * 64
        assert 'archived_integrity' not in kwargs
        output.mkdir(mode=0o700)
        for path in directory.iterdir():
            shutil.copyfile(path, output / path.name)
        return output / subject.completion.MANIFEST
    monkeypatch.setattr(subject.completion, 'assemble', reconstruct)
    common = {'release-auth.py': source['tools/release-auth.py'], 'MANIFEST.txt': manifest,
              **{'aria2c-' + arch: source['deliverables/aria2c-' + arch] for arch in ('x86_64', 'aarch64')},
              'aria2c.sha256': ''.join(proofs['aria2']['binary_sha256'][arch] + '  aria2c-' + arch + '\n'
                                      for arch in ('x86_64', 'aarch64')).encode(),
              proofs['aria2']['asset'] + '.sha256': (proofs['aria2']['archive_sha256'] + '  ' + proofs['aria2']['asset'] + '\n').encode(),
              'iris.tgz.sha256': (sha(originals['iris.tgz']) + '  iris.tgz\n').encode()}
    digest = seal()
    assets = {**evidence['files'], subject.completion.MANIFEST: row(encoded(evidence)),
              **{name: row(raw) for name, raw in common.items()}}
    refs = {role: {'asset': proof['asset'], 'sha256': proof['archive_sha256']} for role, proof in proofs.items()}
    review = {'format': subject.REVIEW_SCHEMA, 'scope': 'source-sufficiency-and-redistribution',
              'decision': 'approve-exact-artifacts', 'tag': TAG, 'commit': COMMIT,
              'candidate_evidence_sha256': digest, 'payload_assets': assets,
              'payload_asset_map_sha256': sha(encoded(assets)), 'image_inventory_sha256': evidence['image_inventory_sha256'],
              'companions': refs, 'reviewer': 'Fixture reviewer', 'reference': 'Fixture-only review',
              'statement': 'Test statement, not actual owner approval.'}
    stage = {'schema': 'iris-release-stage-v1', 'repository': subject.kit._auth().REPOSITORY,
             'workflow': subject.kit._auth().WORKFLOW, 'tag': TAG, 'commit': COMMIT, 'run_id': 123, 'run_attempt': 2}
    write(tmp_path / 'review.json', encoded(review))
    write(tmp_path / 'stage.json', encoded(stage))
    return SimpleNamespace(directory=directory, evidence=evidence, candidate=candidate, payload=payload,
        source=source, entries=entries, tree=tree, seal=seal, digest=digest, calls=calls, common=common,
        assets=assets, refs=refs, review=review, stage=stage, tmp=tmp_path)


def options(g):
    return dict(repository=g.tmp / 'repository', tag=TAG, commit=COMMIT,
                debian_keyring=g.tmp / 'keyring.gpg', pip_sdist_sha256='d' * 64)


def prepare(g):
    return dict(directory=g.directory, expected_evidence_sha256=g.digest, output_dir=g.tmp / 'output',
                **options(g), source_review=g.tmp / 'review.json', expected_review_sha256=sha(encoded(g.review)),
                stage_record=g.tmp / 'stage.json', expected_stage_sha256=sha(encoded(g.stage)))


def test_check_reconstructs_and_derives_exact_common_deliveries(gate):
    g = gate
    originals = {path.name: path.read_bytes() for path in g.directory.iterdir()}
    with subject.check_completed_candidate(g.directory, g.digest, **options(g)) as checked:
        private = checked.directory
        assert checked.assets == g.assets
        assert checked.companions == g.refs
        assert checked.delivery_assets == {name: row(raw) for name, raw in g.common.items()}
        assert checked.git_source_parity['canonical_file_count'] == len(g.source)
        assert checked.git_source_parity['binary_rebuild_verified'] is False
        for name, raw in g.common.items():
            assert (private / name).read_bytes() == raw
    assert not private.exists()
    assert len(g.calls) == 1
    assert {path.name: path.read_bytes() for path in g.directory.iterdir()} == originals


def test_prepare_preserves_original_and_stage_before_unsigned_seal(gate):
    g = gate
    path = subject.prepare_prebuilt(**prepare(g))
    report = subject.kit._json(path.read_bytes())
    release = subject.kit._json((path.parent / 'release.json').read_bytes())
    assert report['payload_assets'] == g.assets
    assert report['payload_asset_map_sha256'] == sha(encoded(g.assets))
    assert report['stage_record_sha256'] == sha(encoded(g.stage))
    assert report['staged_run'] == {'run_id': 123, 'run_attempt': 2}
    assert report['source_review_sha256'] == sha(encoded(g.review))
    for key in ('authenticated', 'source_coverage_complete', 'rebuild_verified', 'review_statement_authenticated'):
        assert report[key] is False
    assert 'not reviewer identity or approval authority' in report['review_attribution']['authority']
    assert set(release['assets']) == {*g.assets, subject.REVIEW_NAME, subject.PREPARATION_NAME, subject.STAGE_NAME}
    assert (path.parent / subject.REVIEW_NAME).read_bytes() == encoded(g.review)
    assert (path.parent / subject.STAGE_NAME).read_bytes() == encoded(g.stage)
    for name, item in release['assets'].items():
        assert subject.completion._file(path.parent / name) == item
        assert (path.parent / name).stat().st_mode & 0o777 == 0o444
    sums = {**release['assets'], 'release.json': row((path.parent / 'release.json').read_bytes())}
    assert (path.parent / 'SHA256SUMS').read_bytes() == ''.join(
        item['sha256'] + '  ' + name + '\n' for name, item in sorted(sums.items())).encode()


@pytest.mark.parametrize('fault', ['external-digest', 'extra', 'missing', 'tamper', 'symlink', 'hardlink',
    'unknown-field', 'authenticated', 'coverage', 'rebuild', 'profile', 'tag', 'commit', 'null-files',
    'boolean-size', 'reserved', 'missing-companion', 'wrong-companion', 'alias-companion', 'original-digest',
    'original-null', 'original-tag', 'original-file', 'missing-evidence'])
def test_completed_faults_refuse_before_output(gate, fault):
    g, kwargs = gate, prepare(gate)
    if fault == 'external-digest':
        kwargs['expected_evidence_sha256'] = '0' * 64
    elif fault == 'extra':
        write(g.directory / 'extra', b'preserve')
    elif fault in ('missing', 'tamper', 'symlink', 'hardlink'):
        path = g.directory / 'iris.tgz'
        if fault == 'tamper':
            write(path, b'changed')
        else:
            original = g.tmp / 'retained'
            path.rename(original)
            if fault == 'symlink':
                path.symlink_to(original)
            elif fault == 'hardlink':
                os.link(original, path)
    elif fault == 'unknown-field':
        g.evidence['trusted'] = True
    elif fault in ('authenticated', 'coverage', 'rebuild'):
        g.evidence[{'coverage': 'source_coverage_complete', 'rebuild': 'rebuild_verified'}.get(fault, fault)] = True
    elif fault in ('profile', 'tag', 'commit'):
        g.evidence[fault] = 'unsupported'
    elif fault == 'null-files':
        g.evidence['files'] = None
    elif fault == 'boolean-size':
        g.evidence['files']['iris.tgz']['size'] = True
    elif fault == 'reserved':
        g.evidence['files']['release-stage.json'] = row(b'bad')
    elif fault == 'missing-companion':
        del g.evidence['companions']['runtime']
    elif fault == 'wrong-companion':
        g.evidence['companions']['runtime']['archive_sha256'] = '0' * 64
    elif fault == 'alias-companion':
        g.evidence['companions']['runtime'] = g.evidence['companions']['alpine']
    elif fault == 'original-digest':
        g.evidence['original_candidate_sha256'] = '0' * 64
    elif fault.startswith('original-'):
        if fault == 'original-null':
            raw = b'null'
        else:
            g.candidate['tag' if fault == 'original-tag' else 'files'] = 'bad'
            raw = encoded(g.candidate)
        write(g.directory / subject.completion.ORIGINAL, raw)
        g.evidence['files'][subject.completion.ORIGINAL] = row(raw)
        g.evidence['original_candidate_sha256'] = sha(raw)
    elif fault == 'missing-evidence':
        (g.directory / subject.completion.MANIFEST).unlink()
    if fault not in ('external-digest', 'missing-evidence'):
        kwargs['expected_evidence_sha256'] = g.seal()
    with pytest.raises((InstallError, OSError)):
        subject.prepare_prebuilt(**kwargs)
    assert not kwargs['output_dir'].exists()


@pytest.mark.parametrize('field', sorted(subject.REVIEW_FIELDS))
def test_every_review_field_bound_or_validated(gate, field):
    g = gate
    g.review[field] = '' if field in ('reviewer', 'reference', 'statement') else None
    write(g.tmp / 'review.json', encoded(g.review))
    with pytest.raises(InstallError):
        subject.prepare_prebuilt(**prepare(g))
    assert not (g.tmp / 'output').exists()


@pytest.mark.parametrize('field,value', [('payload_assets', {}), ('payload_asset_map_sha256', '0' * 64),
    ('statement', 'x' * 8193), ('statement', 'bad\x00text'), ('reviewer', False), ('decision', True)])
def test_review_wrong_byte_maps_and_unbounded_attribution_refuse(gate, field, value):
    gate.review[field] = value
    write(gate.tmp / 'review.json', encoded(gate.review))
    with pytest.raises(InstallError):
        subject.prepare_prebuilt(**prepare(gate))


@pytest.mark.parametrize('field,value', [('schema', 1), ('repository', 'other/repo'), ('workflow', 'other/workflow'),
    ('tag', 'v2026.10.08'), ('commit', 'b' * 40), ('run_id', True), ('run_id', 0), ('run_id', 2**63),
    ('run_attempt', -1), ('run_attempt', '1')])
def test_stage_record_refuses_before_expensive_checks(gate, field, value):
    gate.stage[field] = value
    write(gate.tmp / 'stage.json', encoded(gate.stage))
    with pytest.raises(InstallError):
        subject.prepare_prebuilt(**prepare(gate))
    assert not gate.calls
    assert not (gate.tmp / 'output').exists()


@pytest.mark.parametrize('which', ['review', 'stage'])
def test_external_statement_digest_cannot_be_adopted(gate, which):
    kwargs = prepare(gate)
    kwargs['expected_' + which + '_sha256'] = '0' * 64
    with pytest.raises(InstallError):
        subject.prepare_prebuilt(**kwargs)
    assert not gate.calls


@pytest.mark.parametrize('fault', ['manifest', 'missing-helper', 'wrong-client', 'trailing-gzip'])
def test_delivery_source_faults_refuse(gate, fault):
    g = gate
    if fault == 'manifest':
        g.entries['iris/MANIFEST.txt'] = b'incorrect manifest\n'
    elif fault == 'missing-helper':
        del g.entries['iris/tools/release-auth.py']
    elif fault == 'wrong-client':
        g.evidence['companions']['aria2']['binary_sha256']['aarch64'] = '0' * 64
    raw = tar(g.entries) + (b'forged tail' if fault == 'trailing-gzip' else b'')
    write(g.directory / 'iris.tgz', raw)
    g.candidate['files']['iris.tgz'] = row(raw)
    with pytest.raises((InstallError, OSError)):
        subject._delivery_assets(g.directory, g.candidate, g.evidence, g.refs)


def test_reconstructed_evidence_must_be_byte_identical(gate, monkeypatch):
    original = subject.completion.assemble
    def changed(*args, **kwargs):
        path = original(*args, **kwargs)
        write(path, path.read_bytes() + b' ')
        return path
    monkeypatch.setattr(subject.completion, 'assemble', changed)
    with pytest.raises(InstallError, match='independent reconstruction'):
        subject.prepare_prebuilt(**prepare(gate))
    assert not (gate.tmp / 'output').exists()


def test_ubuntu_profile_requires_and_forwards_exact_companion(gate):
    g = gate
    g.candidate['profile'] = g.evidence['profile'] = 'ubuntu-dependencies'
    dependency = 'iris-ubuntu-dependencies.tar.gz'
    write(g.directory / dependency, b'authenticated dependency fixture')
    g.candidate['files'][dependency] = row(b'authenticated dependency fixture')
    g.evidence['files'][dependency] = g.candidate['files'][dependency]
    original = encoded(g.candidate)
    write(g.directory / subject.completion.ORIGINAL, original)
    g.evidence['original_candidate_sha256'] = sha(original)
    g.evidence['files'][subject.completion.ORIGINAL] = row(original)
    name, raw = 'iris-ubuntu-sources.tar.gz', b'ubuntu source companion'
    write(g.directory / name, raw)
    g.evidence['files'][name] = row(raw)
    g.evidence['companions']['ubuntu'] = {'asset': name, 'archive_sha256': sha(raw), 'scope': 'ubuntu'}
    with subject.check_completed_candidate(g.directory, g.seal(), **options(g)) as checked:
        assert checked.companions['ubuntu'] == {'asset': name, 'sha256': sha(raw)}
    assert g.calls[0]['ubuntu_sources'].name == name
    del g.evidence['companions']['ubuntu']
    with pytest.raises(InstallError, match='exact profile companion'):
        with subject.check_completed_candidate(g.directory, g.seal(), **options(g)):
            pass


def test_selected_git_cannot_drift_during_validation(gate, monkeypatch):
    calls = []
    def selection(*args):
        calls.append(True)
        return gate.tree if len(calls) == 1 else {}
    monkeypatch.setattr(subject, '_git_selection', selection)
    with pytest.raises(InstallError, match='Git source changed'):
        subject.prepare_prebuilt(**prepare(gate))
    assert not (gate.tmp / 'output').exists()


def test_private_work_substitution_preserves_replacement_sentinel(gate, monkeypatch):
    original = subject._delivery_assets
    replacement = []
    def substituted(payload, *args, **kwargs):
        result = original(payload, *args, **kwargs)
        work = payload.parent
        work.rename(gate.tmp / 'saved-private-work')
        work.mkdir(mode=0o700)
        write(work / 'sentinel', b'owner data')
        replacement.append(work)
        return result
    monkeypatch.setattr(subject, '_delivery_assets', substituted)
    try:
        with pytest.raises(InstallError):
            subject.prepare_prebuilt(**prepare(gate))
        assert (replacement[0] / 'sentinel').read_bytes() == b'owner data'
        assert not (gate.tmp / 'output').exists()
    finally:
        for work in replacement:
            (work / 'sentinel').unlink()
            work.rmdir()


def test_statement_bytes_are_preserved_not_reformatted(gate):
    kwargs = prepare(gate)
    for kind, value in [('review', gate.review), ('stage', gate.stage)]:
        raw = json.dumps(value, indent=2).encode() + b'\n'
        write(gate.tmp / (kind + '.json'), raw)
        kwargs['expected_' + kind + '_sha256'] = sha(raw)
    path = subject.prepare_prebuilt(**kwargs)
    assert (path.parent / subject.REVIEW_NAME).read_bytes() == (gate.tmp / 'review.json').read_bytes()
    assert (path.parent / subject.STAGE_NAME).read_bytes() == (gate.tmp / 'stage.json').read_bytes()


def test_checker_exit_guard_precedes_publication(gate, monkeypatch):
    original = subject.check_completed_candidate
    @contextmanager
    def guarded(*args, **kwargs):
        with original(*args, **kwargs) as checked:
            yield checked
            raise InstallError('input custody lost on context exit')
    monkeypatch.setattr(subject, 'check_completed_candidate', guarded)
    with pytest.raises(InstallError, match='custody'):
        subject.prepare_prebuilt(**prepare(gate))
    assert not (gate.tmp / 'output').exists()


def test_publication_refuses_parent_substitution_and_preserves_sentinel(gate, monkeypatch):
    parent = gate.tmp / 'parent'
    parent.mkdir(mode=0o700)
    saved = gate.tmp / 'saved'
    original = subject.check_completed_candidate
    @contextmanager
    def substituted(*args, **kwargs):
        with original(*args, **kwargs) as checked:
            yield checked
            parent.rename(saved)
            parent.mkdir(mode=0o700)
            write(parent / 'sentinel', b'owner data')
    monkeypatch.setattr(subject, 'check_completed_candidate', substituted)
    kwargs = prepare(gate)
    kwargs['output_dir'] = parent / 'output'
    with pytest.raises(InstallError):
        subject.prepare_prebuilt(**kwargs)
    assert (parent / 'sentinel').read_bytes() == b'owner data'
    assert not (parent / 'output').exists()


def test_existing_output_is_never_replaced(gate):
    output = gate.tmp / 'output'
    output.mkdir(mode=0o700)
    write(output / 'sentinel', b'owner data')
    with pytest.raises((InstallError, OSError)):
        subject.prepare_prebuilt(**prepare(gate))
    assert (output / 'sentinel').read_bytes() == b'owner data'


def test_checked_payload_cannot_drift_before_copy(gate, monkeypatch):
    original = subject._review
    def drift(raw, checked, **kwargs):
        result = original(raw, checked, **kwargs)
        write(checked.directory / 'iris.tgz', b'changed')
        return result
    monkeypatch.setattr(subject, '_review', drift)
    with pytest.raises(InstallError, match='changed before'):
        subject.prepare_prebuilt(**prepare(gate))
    assert not (gate.tmp / 'output').exists()


def git(repository, *arguments):
    return subprocess.check_output(['git', '-C', str(repository), *arguments], text=True).strip()


@pytest.fixture
def repository(tmp_path):
    path = tmp_path / 'fixture-repository'
    path.mkdir(mode=0o700)
    git(path, 'init', '-q')
    git(path, 'config', 'user.name', 'Fixture')
    git(path, 'config', 'user.email', 'fixture@example.invalid')
    builder = subject.completion._helper('build-release-candidate.py')
    for name in builder.BUILDERS:
        write(path / 'tools' / name, b'# fixture\n', 0o644)
    write(path / 'VERSION', TAG[1:].encode() + b'\n', 0o644)
    git(path, 'add', '.')
    git(path, 'commit', '-qm', 'Fixture only')
    commit = git(path, 'rev-parse', 'HEAD')
    # Tags exist solely in this disposable test repository, never shared refs.
    git(path, 'tag', TAG)
    return path, commit


def test_real_git_selection_and_no_configured_hook_execution(repository):
    path, commit = repository
    git(path, 'config', 'core.fsmonitor', '/must-not-execute-fixture-monitor')
    git(path, 'config', 'filter.fixture.clean', '/must-not-execute-fixture-filter')
    tree = subject._git_selection(path, TAG, commit)
    assert 'VERSION' in tree
    assert tree['VERSION']['mode'] == 0o644


@pytest.mark.parametrize('fault', ['head', 'tag', 'version', 'dirty', 'mode'])
def test_real_git_identity_or_raw_source_drift_refuses(repository, fault):
    path, commit = repository
    if fault == 'head':
        commit = '0' * 40
    elif fault == 'tag':
        git(path, 'tag', '-d', TAG)
    elif fault == 'version':
        write(path / 'VERSION', b'2026.10.08\n', 0o644)
    else:
        filename = next(iter(subject.completion._helper('build-release-candidate.py').BUILDERS))
        if fault == 'dirty':
            write(path / 'tools' / filename, b'changed', 0o644)
        else:
            (path / 'tools' / filename).chmod(0o755)
    with pytest.raises((InstallError, OSError)):
        subject._git_selection(path, TAG, commit)


@pytest.mark.parametrize('fault', ['omitted', 'extra', 'mode', 'blob', 'sidecar-digest'])
def test_exact_git_shipping_set_parity(gate, fault):
    tree = deepcopy(gate.tree)
    if fault == 'omitted':
        tree['tools/missing.py'] = tree['VERSION']
    elif fault == 'extra':
        del tree['tools/release-auth.py']
    elif fault == 'mode':
        tree['VERSION']['mode'] = 0o755
    elif fault == 'blob':
        tree['VERSION']['blob'] = '0' * 40
    else:
        name = 'fixture.deb.source.json'
        value = subject.kit._json((gate.directory / name).read_bytes())
        value['files']['VERSION'] = '0' * 64
        write(gate.directory / name, encoded(value))
    with pytest.raises(InstallError):
        subject._git_source_parity(gate.directory, gate.candidate, tree)


@pytest.mark.parametrize('extra', [[], ['--check', '--source-review', '/tmp/review'], ['--output-dir', '/tmp/output']])
def test_cli_requires_explicit_mode_and_all_external_statements(extra, capsys):
    base = ['--completed-dir', '/tmp/missing', '--evidence-sha256', 'a' * 64, '--repository', '/tmp/missing',
            '--tag', TAG, '--commit', COMMIT, '--debian-keyring', '/tmp/keyring', '--pip-sdist-sha256', 'b' * 64]
    with pytest.raises(SystemExit) as error:
        subject.main(base + extra)
    assert error.value.code == 2
    assert 'Traceback' not in capsys.readouterr().err


def test_cli_check_failure_is_concise(capsys):
    args = ['--check', '--completed-dir', '/tmp/missing', '--evidence-sha256', 'a' * 64,
            '--repository', '/tmp/missing', '--tag', TAG, '--commit', COMMIT,
            '--debian-keyring', '/tmp/keyring', '--pip-sdist-sha256', 'b' * 64]
    with pytest.raises(SystemExit) as error:
        subject.main(args)
    assert error.value.code == 1
    assert 'Traceback' not in capsys.readouterr().err
