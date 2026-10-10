# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Public package selection binds source and controller without trusting a checkout."""

import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import upgrade_candidate as candidate, upgrade_plan as plan
from iris_installer.state import InstallError, atomic_write

COMMIT = 'a' * 40


@pytest.fixture
def selection(tmp_path, monkeypatch):
    source = tmp_path / 'source'; source.mkdir()
    atomic_write(source / 'VERSION', b'2026.10.10\n', 0o644)
    runtime = {name: hashlib.sha256(name.encode()).hexdigest()
               for name in ('__init__.py', 'managed_worker.py', 'lifecycle_worker.py', 'state.py')}
    manifest = {'tools/iris_installer/' + name: digest for name, digest in runtime.items()}
    manifest['VERSION'] = hashlib.sha256(b'2026.10.10\n').hexdigest()
    atomic_write(source / 'INSTALLER-SOURCE.json', plan.canonical(manifest), 0o644)
    proof = tmp_path / 'iris-installer.deb.source.json'
    raw = plan.canonical({'schema': 1, 'commit': COMMIT, 'files': manifest})
    atomic_write(proof, raw, 0o644)
    result = {'version': b'install ok installed\n2026.10.10+installer.0.gaaaaaaaaaaaa\n'}
    calls = []
    def command(argv, **kwargs):
        calls.append(argv)
        return result['version']
    install = SimpleNamespace(command=command,
        journal=SimpleNamespace(document={'source_manifest': {'old.py': '0' * 64}}))
    # Host-root custody has its own real permission tests. This unit executes
    # the content contracts as the invoking test user, with no apt operation.
    monkeypatch.setattr(candidate.managed_worker, '_path', lambda path: Path(path))
    monkeypatch.setattr(candidate.managed_worker, '_runtime_manifest', lambda: runtime)
    return SimpleNamespace(source=source, proof=proof, raw=raw, digest=hashlib.sha256(raw).hexdigest(),
        runtime=runtime, manifest=manifest, install=install, result=result, calls=calls)


def test_explicit_package_source_proof_and_installed_runtime_are_bound(selection):
    value, raw = candidate.selected_source(selection.install, selection.source, selection.proof,
                                           selection.digest, COMMIT)
    assert raw == selection.raw and value['source'] == selection.manifest
    assert value['runtime'] == selection.runtime and value['commit'] == COMMIT
    assert selection.calls == [['dpkg-query', '-W', '-f=${Status}\n${Version}\n', 'iris-installer']]


@pytest.mark.parametrize('damage', ['digest', 'commit', 'runtime', 'inventory', 'package-version',
                                  'package-status', 'same-source', 'boolean-schema', 'writable-proof'])
def test_unapproved_or_dirty_generations_are_rejected(selection, damage):
    selected = selection
    digest, commit = selected.digest, COMMIT
    if damage == 'digest': digest = '0' * 64
    elif damage == 'commit': commit = 'b' * 40
    elif damage == 'runtime': selected.runtime['state.py'] = 'f' * 64
    elif damage == 'inventory':
        atomic_write(selected.source / 'INSTALLER-SOURCE.json', plan.canonical({'dirty.py': 'f' * 64}), 0o644)
    elif damage == 'package-version': selected.result['version'] = b'install ok installed\n2026.10.09+installer.0.gaaaaaaaaaaaa\n'
    elif damage == 'package-status': selected.result['version'] = b'deinstall ok config-files\n2026.10.10+installer.0.gaaaaaaaaaaaa\n'
    elif damage == 'same-source': selected.install.journal.document['source_manifest'] = selected.manifest
    elif damage == 'boolean-schema':
        raw = plan.canonical({'schema': True, 'commit': COMMIT, 'files': selected.manifest})
        atomic_write(selected.proof, raw, 0o644); digest = hashlib.sha256(raw).hexdigest()
    elif damage == 'writable-proof': selected.proof.chmod(0o666)
    with pytest.raises(InstallError):
        candidate.selected_source(selected.install, selected.source, selected.proof, digest, commit)


def test_declared_source_proof_does_not_waive_actual_source_hashes(selection, tmp_path):
    selected = selection
    # Real snapshot checks each declared byte, including a declared file that
    # is missing. No build command is allowed to run on this broken candidate.
    selected.source.joinpath('VERSION').write_bytes(b'2026.10.09\n')
    with pytest.raises((InstallError, FileNotFoundError)):
        candidate.deploy.snapshot(selected.source, tmp_path / 'candidate')


def test_runtime_contract_bool_is_not_an_integer():
    old = {'services': {'iris': {'read_only': True}, 'console': {}}}
    new = {'services': {'iris': {'read_only': 1}, 'console': {}}}
    with pytest.raises(InstallError, match='runtime layout'):
        plan.candidate_compose(old, old, new, {'iris': 'sha256:' + '1' * 64, 'console': 'sha256:' + '2' * 64})


def test_upgrade_cli_requires_explicit_operation_plan_and_package_proof():
    from iris_installer.cli import parser
    value = parser().parse_args(['upgrade', 'recover', '--state-dir', '/state', '--operation-id',
        '7f761c39-450f-4101-836e-6515449d7b28', '--plan-sha256', 'a' * 64, '--allow-downtime'])
    assert value.upgrade_action == 'recover' and value.allow_downtime is True
    with pytest.raises(SystemExit):
        parser().parse_args(['upgrade', 'apply', '--state-dir', '/state'])
    with pytest.raises(SystemExit):
        parser().parse_args(['upgrade', 'prepare', '--state-dir', '/state', '--accept-changes'])
