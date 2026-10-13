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
import tarfile
import threading
from types import SimpleNamespace
import urllib.request

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


@pytest.mark.parametrize('damage', ['obsolete-name', 'extra-alias', 'missing-sidecar'])
def test_upgrade_guest_outputs_require_the_exact_served_names(damage):
    expected = {'iris-agent.tgz', 'iris-agent.tgz.sha256',
                'iris-agent-arm.tgz', 'iris-agent-arm.tgz.sha256'}
    assert plan.GUEST_FILES == expected
    files = {name: 'a' * 64 for name in plan.BUILD_FILES}
    plan.file_manifest(files, expected=plan.BUILD_FILES)
    if damage == 'obsolete-name':
        for suffix in ('', '.sha256'):
            files['iris-agent-arm64.tgz' + suffix] = files.pop('iris-agent-arm.tgz' + suffix)
    elif damage == 'extra-alias':
        files['iris-agent-arm64.tgz'] = 'a' * 64
    else:
        files.pop('iris-agent-arm.tgz.sha256')
    with pytest.raises(InstallError, match='incomplete or unexpected'):
        plan.file_manifest(files, expected=plan.BUILD_FILES)


def test_upgrade_cli_requires_explicit_operation_plan_and_package_proof():
    from iris_installer.cli import parser
    value = parser().parse_args(['upgrade', 'recover', '--state-dir', '/state', '--operation-id',
        '7f761c39-450f-4101-836e-6515449d7b28', '--plan-sha256', 'a' * 64, '--allow-downtime'])
    assert value.upgrade_action == 'recover' and value.allow_downtime is True
    with pytest.raises(SystemExit):
        parser().parse_args(['upgrade', 'apply', '--state-dir', '/state'])
    with pytest.raises(SystemExit):
        parser().parse_args(['upgrade', 'prepare', '--state-dir', '/state', '--accept-changes'])


@pytest.mark.parametrize('damage', [None, 'verifier-build', 'crypto-build',
    'missing-verifier-arm64', 'wrong-verifier-arm64', 'missing-aead-amd64',
    'wrong-aead-arm64', 'missing-verifier-license', 'missing-aead-license', 'one-root'])
def test_candidate_builds_helpers_and_runs_actual_bundle_packer(tmp_path, monkeypatch, damage):
    """Real helper scripts/packer, but nonexecuted ELF stand-ins, not native proof."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    repository = Path(__file__).resolve().parents[2]
    source = tmp_path / 'selected source'; source.mkdir()
    scripts = ('tools/get-ioxclient.sh', 'tools/stage-iox-package.sh',
               'tools/build-xr-package.sh', 'tools/build-device-image.sh',
               'tools/build-ssh-verifiers.sh', 'tools/build-instruction-crypto.sh',
               'tools/build-instruction-crypto.Dockerfile', 'server/Dockerfile',
               'server/pack-agent-bundle.sh', 'server/instruction_keys.py',
               'device/verify_image.py', 'device/bootstrap.sh',
               'device/guestshell-start.sh', 'device/rotate-logs.sh',
               'device/agent/peer-transfer-hook.sh', 'bin/.gitkeep')
    manifest = {}
    for name in (*scripts, *(path.relative_to(repository).as_posix()
                            for path in (repository / 'device/agent').glob('*.py'))):
        raw = (repository / name).read_bytes()
        (source / name).parent.mkdir(parents=True, exist_ok=True)
        atomic_write(source / name, raw, 0o755)
        manifest[name] = hashlib.sha256(raw).hexdigest()
    def elf(machine):
        return b'\x7fELF\x02\x01' + bytes(12) + machine.to_bytes(2, 'little') + b'nonexecuted test fixture'
    (source / 'deliverables').mkdir()
    for name, machine in (('aria2c-x86_64', 62), ('aria2c-aarch64', 183)):
        raw = elf(machine)
        atomic_write(source / 'deliverables' / name, raw, 0o755)
        manifest['deliverables/' + name] = hashlib.sha256(raw).hexdigest()
    atomic_write(source / 'INSTALLER-SOURCE.json', plan.canonical(manifest), 0o644)
    base = tmp_path / 'existing installation'; base.mkdir()
    roots = base / 'roots'; roots.mkdir()
    for index in range(1 if damage == 'one-root' else 2):
        public = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        atomic_write(roots / (str(index) + '.pub'), public + b'\n', 0o644)
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
    helpers = binary / 'guest-helpers'
    # Only Docker's build outputs are simulated. Both real helper scripts must
    # select the operation destination, build both arches and publish licenses.
    commands = tmp_path / 'test commands'; commands.mkdir()
    scratch = tmp_path / 'builder scratch'; scratch.mkdir()
    atomic_write(commands / 'docker', b'''#!/usr/bin/python3
import os,sys
from pathlib import Path
args=sys.argv[1:]
assert args[:3]==['buildx','build','--pull']
output=args[args.index('--output')+1]
assert output.startswith('type=local,dest=')
out=Path(output.split('=',2)[2]);out.mkdir(parents=True,exist_ok=True)
damage=os.environ['TEST_HELPER_DAMAGE']
def elf(machine):
 return b'\\x7fELF\\x02\\x01'+bytes(12)+machine.to_bytes(2,'little')+b'nonexecuted test fixture'
if '--target' in args:
 assert args[args.index('--target')+1]=='ssh-verifier-artifacts'
 if damage=='verifier-build':sys.exit(19)
 for arch,machine in (('amd64',62),('arm64',183)):
  if damage=='missing-verifier-'+arch:continue
  (out/('ssh-keygen-'+arch)).write_bytes(elf(62 if damage=='wrong-verifier-'+arch else machine))
 if damage!='missing-verifier-license':(out/'ssh-keygen.LICENCE').write_bytes(b'verifier test license')
else:
 arch=args[args.index('--platform')+1].removeprefix('linux/')
 assert arch in ('amd64','arm64')
 if damage=='crypto-build':sys.exit(19)
 # The real shell builder requires outputs even for invalid-packer fixtures;
 # damage these only after its successful publication in the runner below.
 (out/'iris-aead').write_bytes(elf(62 if arch=='amd64' else 183))
 (out/'iris-aead.LICENCE').write_bytes(b'AEAD test license')
''', 0o755)

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
        elif name in ('build-ssh-verifiers.sh', 'build-instruction-crypto.sh'):
            assert argv[2:] == [str(helpers)]
            if name == 'build-instruction-crypto.sh':
                assert env['IRIS_CRYPTO_ARCHES'] == 'amd64 arm64'
            probe = argv
        else:
            assert name == 'pack-agent-bundle.sh'
            assert argv[2] == str(Path(argv[1]).parents[1] / 'device')
            assert argv[-2:] == ['--instruction-roots-dir', str(base / 'roots')]
            assert Path(argv[4]).parent == artifacts
            assert (Path(argv[3]).name, Path(argv[4]).name) in (
                ('aria2c-x86_64', 'iris-agent.tgz'), ('aria2c-aarch64', 'iris-agent-arm.tgz'))
            arch = 'amd64' if Path(argv[3]).name.endswith('x86_64') else 'arm64'
            assert argv[5:7] == ['--ssh-keygen', str(helpers / ('ssh-keygen-' + arch))]
            assert env['IRIS_AEAD_HELPER'] == str(helpers / ('iris-aead-' + arch))
            probe = argv
        result = subprocess.run(probe, env=env, capture_output=True, timeout=20, check=True)
        if name == 'build-instruction-crypto.sh':
            if damage == 'missing-aead-amd64': (helpers / 'iris-aead-amd64').unlink()
            elif damage == 'wrong-aead-arm64': (helpers / 'iris-aead-arm64').write_bytes(elf(62))
            elif damage == 'missing-aead-license': (helpers / 'iris-aead.LICENCE').unlink()
        if name == 'build-xr-package.sh':
            resolved = [shlex.split(line.split('=', 1)[1]) for line in result.stderr.decode().splitlines()
                        if line.startswith('+ APPMGR_BUILD_DIR=')]
            assert resolved[-1] == [str(operation.directory / 'cache/iris/xr-appmgr-build')]
            assert not (operation.directory / 'cache/iris').exists()
        for filename in plan.BUILD_FILES - plan.GUEST_FILES:
            atomic_write(artifacts / filename, b'unit-test output, not a native package', 0o644)
        return b''

    install = SimpleNamespace(base=base, source=source, compose_file=compose_file,
        env=dict(candidate.deploy.clean_env(), XDG_CACHE_HOME=str(old_cache),
                 PATH=str(commands) + ':' + candidate.deploy.clean_env()['PATH'],
                 TMPDIR=str(scratch),
                 IRIS_CRYPTO_ARCHES='arm64', IRIS_AEAD_HELPER='/must-not-use/inherited-helper',
                 TEST_HELPER_DAMAGE=damage or ''),
        command=command, runner=runner)
    if damage:
        with pytest.raises(subprocess.CalledProcessError) as error:
            candidate.build(install, operation, {'source': manifest}, source)
        assert error.value.returncode == (19 if damage.endswith('-build') else 1)
        assert not (artifacts / 'iris-agent-arm.tgz').exists()
        if not damage.endswith('-build'):
            assert b'pack-agent-bundle:' in error.value.stderr
        if damage == 'crypto-build':
            assert len(list(scratch.iterdir())) == 1
            assert next(scratch.iterdir()).is_dir()
    else:
        built = candidate.build(install, operation, {'source': manifest}, source)
        assert [name for name, unused in calls] == ['get-ioxclient.sh', 'stage-iox-package.sh',
            'stage-iox-package.sh', 'build-xr-package.sh', 'build-ssh-verifiers.sh',
            'build-instruction-crypto.sh', 'pack-agent-bundle.sh', 'pack-agent-bundle.sh']
        assert built['native_admission'] == 'not-qualified-by-this-build'
        for filename, machine in (('iris-agent.tgz', 62), ('iris-agent-arm.tgz', 183)):
            bundle = artifacts / filename
            with tarfile.open(bundle) as archive:
                for name in ('aria2c', 'agent/ssh-keygen', 'agent/iris-aead'):
                    assert archive.extractfile(name).read() == elf(machine)
                assert archive.extractfile('agent/ssh-keygen.LICENCE').read() == b'verifier test license'
                assert archive.extractfile('agent/iris-aead.LICENCE').read() == b'AEAD test license'
                for name in ('iris-signers.allowed_signers', 'iris-root.allowed_signers'):
                    assert archive.extractfile(name).read().count(b'ssh-ed25519') == 2
            assert bundle.with_name(filename + '.sha256').read_text() == hashlib.sha256(bundle.read_bytes()).hexdigest() + '\n'
    for root in (source, base / ('.upgrade-source-' + operation.id)):
        actual = {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in root.rglob('*') if path.is_file() and path.name != 'INSTALLER-SOURCE.json'}
        assert actual == manifest
        assert list((root / 'bin').iterdir()) == [root / 'bin/.gitkeep']
    assert (served / 'sentinel').read_bytes() == b'current served package'
    assert list(served.iterdir()) == [served / 'sentinel']
    assert list(old_cache.iterdir()) == [old_cache / 'sentinel']
    assert (old_cache / 'sentinel').read_bytes() == b'current builder cache'
    if damage is None:
        _assert_candidate_publishes_guest_shell_routes(install, operation, built, monkeypatch)


def _assert_candidate_publishes_guest_shell_routes(install, operation, built, monkeypatch):
    """Real packer -> staged generation -> published public route, no native execution."""
    import artifact_server
    from iris_installer import upgrade_runtime as runtime

    served = install.base / 'artifacts'
    original = {}
    for name in ('iris-agent.tgz', 'iris-agent-arm.tgz'):
        original[name] = ('stale ' + name).encode()
        original[name + '.sha256'] = hashlib.sha256(original[name]).hexdigest().encode() + b'\n'
    original['iris-catalog.pem'] = b'unchanged deployment certificate'
    for name, raw in original.items():
        atomic_write(served / name, raw, 0o644)
    operation.record = {}
    saves = []
    operation.save = lambda: saves.append(plan.canonical(operation.record))
    # Unit tests keep the invoking user's custody. Only chown is modeled;
    # inventory, staging, hash checks, fsync and directory publication are real.
    monkeypatch.setattr(runtime.os, 'chown', lambda *args: None)
    runtime.stage_artifacts(install, operation, built)
    assert len(saves) == 2
    assert all((served / name).read_bytes() == raw for name, raw in original.items())
    staged = install.base / ('.upgrade-artifacts-' + operation.id)
    assert not (staged / 'iris-agent-arm64.tgz').exists()
    for name in ('iris-agent.tgz', 'iris-agent-arm.tgz'):
        assert artifact_server._legacy_guest_shell_target('/' + name) == name
        assert (staged / name).read_bytes() != original[name]
        digest = hashlib.sha256((staged / name).read_bytes()).hexdigest()
        assert digest == built['files'][name]
        assert (staged / (name + '.sha256')).read_bytes() == digest.encode() + b'\n'
    assert artifact_server._legacy_guest_shell_target('/iris-agent-arm64.tgz') is None
    retained = install.base / ('.test-retained-artifacts-' + operation.id)
    runtime.storage.publish(served, staged, retained,
        runtime.storage.fingerprint(operation.record['artifact_before']),
        runtime.storage.fingerprint(operation.record['artifact_after']))
    assert all((retained / name).read_bytes() == raw for name, raw in original.items())
    assert (served / 'iris-catalog.pem').read_bytes() == original['iris-catalog.pem']
    assert (served / 'sentinel').read_bytes() == b'current served package'
    server = artifact_server.make_server('127.0.0.1', 0, str(served))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for name in ('iris-agent.tgz', 'iris-agent-arm.tgz'):
            with urllib.request.urlopen('http://127.0.0.1:%d/%s' % (server.server_address[1], name),
                                        timeout=5) as response:
                assert response.status == 200
                assert hashlib.sha256(response.read()).hexdigest() == built['files'][name]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_iox_parser_rejects_obsolete_upgrade_artifacts_flag_before_any_build(tmp_path):
    script = Path(__file__).resolve().parents[2] / 'tools/stage-iox-package.sh'
    output = tmp_path / 'must-not-be-created'
    result = subprocess.run(['bash', str(script), '--arch', 'arm64', '--artifacts', str(output)],
                            env=candidate.deploy.clean_env(), capture_output=True, timeout=10)
    assert result.returncode == 2 and result.stderr == b'!! unknown option: --artifacts\n'
    assert not output.exists()
