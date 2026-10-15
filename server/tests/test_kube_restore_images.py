# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real authenticated archive recovery with a bounded container-runtime seam."""

import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import backup_archive, kube_restore_images as images
from iris_installer.state import InstallError


def encoded(value):
    return json.dumps(value, sort_keys=True).encode()


def image_archive(path, *, extra=False, classic=False, corrupt=False):
    payload = {}
    roots = []
    for role in ('server', 'console', *(['foreign'] if extra else [])):
        blob = encoded({'architecture': 'amd64', 'role': role, 'rootfs': {'type': 'layers', 'diff_ids': []}})
        digest = hashlib.sha256(blob).hexdigest()
        payload[digest + '.json' if classic else 'blobs/sha256/' + digest] = blob
        roots.append({'digest': 'sha256:' + digest})
    if classic:
        payload['manifest.json'] = encoded([{'Config': row['digest'][7:] + '.json', 'RepoTags': None, 'Layers': []} for row in roots])
    else:
        payload['index.json'] = encoded({'schemaVersion': 2, 'manifests': roots})
    if corrupt:
        key = next(iter(payload));payload[key] = b'changed'
    with tarfile.open(path, 'w') as archive:
        for name, raw in payload.items():
            member = tarfile.TarInfo(name);member.size = len(raw);member.mode = 0o600
            archive.addfile(member, io.BytesIO(raw))
    path.chmod(0o600)
    return [row['digest'] for row in roots]


@pytest.fixture
def runtime(tmp_path):
    source = tmp_path / 'images.tar'
    ids = image_archive(source)
    refs = {role: 'docker.io/iris/test-' + role + '@' + digest for role, digest in zip(('iris', 'console'), ids)}
    builds = dict(zip(('server', 'console'), ids))
    state = {'images': {ref: ref.rsplit('@', 1)[1] for ref in refs.values()}, 'pinned': set(), 'calls': []}
    def command(argv, **kwargs):
        state['calls'].append(list(argv))
        assert argv[0] == 'k3s', 'Recovery must work without Docker'
        if argv[1:] == ['ctr', 'images', 'list']:
            return ('REF TYPE DIGEST SIZE PLATFORMS LABELS\n' + ''.join(
                name + ' application/vnd.oci.image.manifest.v1+json ' + digest + ' 1B linux/amd64 -\n'
                for name, digest in state['images'].items())).encode()
        if argv[1:4] == ['ctr', 'images', 'import']:
            assert argv[4:7] == ['--digests', '--label', images.PIN]
            for digest in ids:
                name = 'imported@' + digest;state['images'][name] = digest;state['pinned'].add(name)
            return b''
        if argv[1:4] == ['ctr', 'images', 'tag']:
            state['images'][argv[5]] = state['images'][argv[4]];return b''
        if argv[1:4] == ['ctr', 'images', 'label']:
            assert argv[5] == images.PIN;state['pinned'].add(argv[4]);return b''
        if argv[1:3] == ['crictl', 'inspecti']:
            ref = argv[3]
            return encoded({'status': {'id': state['images'][ref], 'repoDigests': [ref],
                                       'pinned': ref in state['pinned']}})
        pytest.fail('Unexpected runtime command: ' + repr(argv))
    install = SimpleNamespace(config={'kube_image_import': 'k3s'}, command=command,
        verify_resource_ownership=lambda: state['calls'].append(['ownership']),
        journal=SimpleNamespace(document={'completed': {'images': builds, 'kube-images': refs}}))
    return install, state, source, ids


@pytest.fixture
def authenticated(runtime, tmp_path):
    for executable in ('age', 'age-keygen', 'ssh-keygen'):
        if not shutil.which(executable):pytest.skip(executable + ' required')
    install, state, source, ids = runtime
    identity, signer = tmp_path / 'identity', tmp_path / 'signer'
    subprocess.run(['age-keygen', '-o', str(identity)], capture_output=True, check=True)
    recipient = subprocess.check_output(['age-keygen', '-y', str(identity)]).decode().strip()
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(signer)], check=True)
    backups = tmp_path / 'backups';backups.mkdir(mode=0o700)
    directory = tmp_path / 'operation';directory.mkdir(mode=0o700)
    metadata = {'scope': 'managed-deployment-files', 'image_ids': install.journal.document['completed']['images']}
    envelope = backup_archive.create({'container-images': source}, backups / 'approved', recipient, signer, metadata=metadata)
    trusted = Path(str(signer) + '.pub')
    verified = backup_archive.read(backups / 'approved', identity, trusted)
    tx = SimpleNamespace(directory=directory, backups=backups, backup_id='approved', identity=identity,
                         signer=trusted, record={'data_sha256': envelope['payload_sha256']})
    return tx, verified


def test_present_images_are_pinned_before_simulated_stopped_interval_gc(runtime):
    install, state, _, _ = runtime
    images.prepare(install, None, None)
    # Model kubelet's observed failure trigger: only unused, unpinned images go.
    state['images'] = {ref: value for ref, value in state['images'].items() if ref in state['pinned']}
    assert set(state['images']) == set(install.journal.document['completed']['kube-images'].values())
    assert not any('import' in call for call in state['calls'])


@pytest.mark.parametrize('missing', ['console', 'both'])
def test_real_authenticated_backup_recovers_exact_runtime_without_docker(runtime, authenticated, missing):
    install, state, _, _ = runtime;tx, verified = authenticated
    if missing == 'both':state['images'].clear()
    else:state['images'].pop(install.journal.document['completed']['kube-images']['console'])
    images.prepare(install, tx, verified)
    refs = install.journal.document['completed']['kube-images']
    assert all(state['images'][ref] == ref.rsplit('@', 1)[1] and ref in state['pinned'] for ref in refs.values())
    assert sum('import' in row for row in state['calls']) == 1
    assert not list(tx.directory.iterdir())  # extraction never becomes a new restore authority


def test_wrong_existing_reference_refuses_even_if_first_image_is_missing(runtime):
    install, state, _, _ = runtime;refs = install.journal.document['completed']['kube-images']
    state['images'].pop(refs['iris']);state['images'][refs['console']] = 'sha256:' + 'f' * 64
    with pytest.raises(InstallError, match='changed content'):images.prepare(install, None, None)
    assert not any(row[1:3] == ['ctr', 'images'] and row[3] in ('import', 'label', 'tag') for row in state['calls'] if len(row) > 3)


def test_changed_approved_backup_refuses_before_import(runtime, authenticated):
    install, state, _, _ = runtime;tx, verified = authenticated
    state['images'].clear();tx.record['data_sha256'] = 'f' * 64
    with pytest.raises(InstallError, match='backup bytes changed'):images.prepare(install, tx, verified)
    assert not any('import' in row for row in state['calls'])


def test_failed_pin_verification_refuses_before_stop(runtime, monkeypatch):
    install, state, _, _ = runtime;original = install.command
    def command(argv, **kwargs):
        value = original(argv, **kwargs)
        if argv[1:3] == ['crictl', 'inspecti']:
            result = json.loads(value);result['status']['pinned'] = False;return encoded(result)
        return value
    install.command = command
    ticks = iter((0, 11));monkeypatch.setattr(images.time, 'monotonic', lambda: next(ticks))
    with pytest.raises(InstallError, match='not protected'):images.prepare(install, None, None)


def test_registry_mode_uses_no_local_runtime_commands(runtime):
    install, state, _, _ = runtime;install.config['kube_image_import'] = 'registry'
    images.prepare(install, None, None)
    assert state['calls'] == []


@pytest.mark.parametrize('classic', [False, True])
def test_exact_oci_and_classic_archive_roots(tmp_path, classic):
    path = tmp_path / 'images';ids = image_archive(path, classic=classic)
    images._archive_roots(path, set(ids))


@pytest.mark.parametrize('kind', ['foreign-root', 'corrupt-root', 'symlink', 'public-mode'])
@pytest.mark.parametrize('classic', [False, True])
def test_archive_identity_refuses_foreign_changed_and_unprotected_bytes(tmp_path, kind, classic):
    path = tmp_path / 'images';ids = image_archive(path, classic=classic)
    if kind == 'foreign-root':image_archive(path, extra=True, classic=classic)
    if kind == 'corrupt-root':image_archive(path, corrupt=True, classic=classic)
    if kind == 'symlink':
        original = tmp_path / 'original';path.rename(original);path.symlink_to(original)
    if kind == 'public-mode':path.chmod(0o644)
    with pytest.raises(InstallError):images._archive_roots(path, set(ids))


def test_actual_shared_stop_boundary_protects_images_before_workload_changes(runtime):
    from iris_installer.kube_deploy import KubeInstall
    install, state, _, _ = runtime
    install.pin_runtime = lambda: None
    def first_workload_read(*args):
        assert state['pinned'] == set(install.journal.document['completed']['kube-images'].values())
        raise RuntimeError('protected before workload stop')
    install.get = first_workload_read
    with pytest.raises(RuntimeError, match='protected before workload stop'):
        KubeInstall.stop_writers(install, [])


def test_missing_image_refuses_shared_stop_without_import_or_workload_changes(runtime):
    from iris_installer.kube_deploy import KubeInstall
    install, state, _, _ = runtime
    state['images'].pop(install.journal.document['completed']['kube-images']['console'])
    install.pin_runtime = lambda: None
    install.get = lambda *args: pytest.fail('missing image must refuse before workload access')
    with pytest.raises(InstallError, match='unavailable before stopping'):
        KubeInstall.stop_writers(install, [])
    assert not state['pinned'] and not any('import' in row for row in state['calls'])
