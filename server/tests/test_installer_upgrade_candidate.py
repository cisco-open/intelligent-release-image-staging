# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Public package selection binds source and controller without trusting a checkout."""

import hashlib
import json
from pathlib import Path
import shlex
import subprocess
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


def test_candidate_builder_arguments_reach_actual_script_parsers(tmp_path, monkeypatch):
    """Exercise real parsing only: Docker builds and package bytes are stand-ins."""
    repository = Path(__file__).resolve().parents[2]
    source = tmp_path / 'selected source'; source.mkdir()
    scripts = ('tools/get-ioxclient.sh', 'tools/stage-iox-package.sh',
               'tools/build-xr-package.sh', 'tools/build-device-image.sh',
               'server/pack-agent-bundle.sh')
    manifest = {}
    for name in scripts:
        raw = (repository / name).read_bytes()
        (source / name).parent.mkdir(parents=True, exist_ok=True)
        atomic_write(source / name, raw, 0o755)
        manifest[name] = hashlib.sha256(raw).hexdigest()
    atomic_write(source / 'INSTALLER-SOURCE.json', plan.canonical(manifest), 0o644)
    base = tmp_path / 'existing installation'; base.mkdir()
    served = base / 'artifacts'; served.mkdir()
    atomic_write(served / 'sentinel', b'current served package', 0o644)
    old_cache = base / 'cache'; old_cache.mkdir()
    atomic_write(old_cache / 'sentinel', b'current builder cache', 0o644)
    operation = SimpleNamespace(id='7f761c39-450f-4101-836e-6515449d7b28',
                                directory=base / 'operation')
    operation.directory.mkdir()
    template = {'services': {name: {'image': 'existing-' + name,
        'build': {'context': str(source), 'dockerfile': name + '/Dockerfile'}}
        for name in plan.SERVICES}}
    compose_file = base / 'compose.json'
    atomic_write(compose_file, plan.canonical(template), 0o644)
    monkeypatch.setattr(candidate, 'template', lambda *args: template)
    calls = []
    artifacts = operation.directory / 'artifacts'
    binary = operation.directory / 'bin'

    def command(argv, **kwargs):
        if argv[:3] == ['docker', 'image', 'inspect']:
            digit = '1' if str(argv[-1]).endswith(':iris') else '2'
            return plan.canonical([{'Id': 'sha256:' + digit * 64}])
        assert argv[:2] == ['docker', 'compose'] and 'build' in argv
        return b''

    def runner(argv, *, env, timeout):
        assert argv[0] == 'bash' and timeout == 7200
        name = Path(argv[1]).name; calls.append((name, argv[2:]))
        assert env['IRIS_INSTRUCTION_ROOTS_DIR'] == str(base / 'roots')
        assert env['IRIS_DEVICE_IMAGE_OCI'] == str(artifacts / 'device.oci.tar')
        assert env['IOXCLIENT'] == str(binary / 'ioxclient')
        assert env['XDG_CACHE_HOME'] == str(operation.directory / 'cache')
        assert 'IRIS_CACHE_DIR' not in env
        if name == 'get-ioxclient.sh':
            assert argv[2:] == [str(binary)]
            # The real supported existing-local-tool branch avoids downloads.
            atomic_write(binary / 'ioxclient', b'parser-test tool, never executed', 0o755)
            probe = argv
        elif name == 'stage-iox-package.sh':
            assert argv[2:] in (['--arch', arch, '--artifacts-dir', str(artifacts)]
                                for arch in ('arm64', 'amd64'))
            probe = [*argv, '--help']
        elif name == 'build-xr-package.sh':
            assert argv[2:] == ['--out', str(artifacts)]
            # The actual no-write dry-run also resolves the default builder
            # cache. Trace contains only these public temporary test inputs.
            probe = ['bash', '-x', *argv[1:], '--dry-run']
        else:
            assert name == 'pack-agent-bundle.sh'
            assert argv[2] == str(Path(argv[1]).parents[1] / 'device')
            assert argv[-2:] == ['--instruction-roots-dir', str(base / 'roots')]
            assert Path(argv[4]).parent == artifacts
            assert (Path(argv[3]).name, Path(argv[4]).name) in (
                ('aria2c-x86_64', 'iris-agent.tgz'), ('aria2c-aarch64', 'iris-agent-arm64.tgz'))
            # This packer has no help mode. Its exact final rejection proves
            # all preceding arguments parsed, before filesystem/build actions.
            probe = [*argv, '--parser-test-stop']
        result = subprocess.run(probe, env=env, capture_output=True, timeout=10)
        if name == 'pack-agent-bundle.sh':
            assert result.returncode == 2
            assert result.stderr == b'pack-agent-bundle: unknown argument: --parser-test-stop\n'
        else:
            assert result.returncode == 0, result.stderr.decode()
        if name == 'build-xr-package.sh':
            resolved = [shlex.split(line.split('=', 1)[1]) for line in result.stderr.decode().splitlines()
                        if line.startswith('+ APPMGR_BUILD_DIR=')]
            assert resolved[-1] == [str(operation.directory / 'cache/iris/xr-appmgr-build')]
            assert not (operation.directory / 'cache/iris').exists()
        for filename in plan.BUILD_FILES:
            atomic_write(artifacts / filename, b'unit-test output, not a native package', 0o644)
        return b''

    install = SimpleNamespace(base=base, source=source, compose_file=compose_file,
        env=dict(candidate.deploy.clean_env(), XDG_CACHE_HOME=str(old_cache)),
        command=command, runner=runner)
    built = candidate.build(install, operation, {'source': manifest}, source)
    assert [name for name, unused in calls] == ['get-ioxclient.sh', 'stage-iox-package.sh',
        'stage-iox-package.sh', 'build-xr-package.sh', 'pack-agent-bundle.sh', 'pack-agent-bundle.sh']
    assert built['native_admission'] == 'not-qualified-by-this-build'
    assert (served / 'sentinel').read_bytes() == b'current served package'
    assert list(served.iterdir()) == [served / 'sentinel']
    assert list(old_cache.iterdir()) == [old_cache / 'sentinel']
    assert (old_cache / 'sentinel').read_bytes() == b'current builder cache'


def test_iox_parser_rejects_obsolete_upgrade_artifacts_flag_before_any_build(tmp_path):
    script = Path(__file__).resolve().parents[2] / 'tools/stage-iox-package.sh'
    output = tmp_path / 'must-not-be-created'
    result = subprocess.run(['bash', str(script), '--arch', 'arm64', '--artifacts', str(output)],
                            env=candidate.deploy.clean_env(), capture_output=True, timeout=10)
    assert result.returncode == 2 and result.stderr == b'!! unknown option: --artifacts\n'
    assert not output.exists()
