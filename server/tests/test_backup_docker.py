# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Opt-in real Docker storage rehearsal; no IRIS fleet or external ports.

sudo env IRIS_BACKUP_DOCKER_IMAGE=<existing immutable image id> \
  PYTHONDONTWRITEBYTECODE=1 python3 -m pytest server/tests/test_backup_docker.py -q -p no:cacheprovider
The image must contain /bin/sh and sleep. Every resource has a unique owner.
"""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from types import SimpleNamespace
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import backup, backup_archive
from iris_installer import lifecycle_worker
from iris_installer.deploy import DockerInstall
from iris_installer.state import Journal


def docker(*args):
    return subprocess.check_output(['docker', *map(str, args)], stderr=subprocess.PIPE)


@pytest.fixture
def deployment(tmp_path):
    image = os.environ.get('IRIS_BACKUP_DOCKER_IMAGE')
    if not image or os.geteuid() != 0:
        pytest.skip('explicit cached test image and root required for Docker volume capture')
    image_id = json.loads(docker('image', 'inspect', image))[0]['Id']
    assert image_id == image, 'use an immutable image ID, not a mutable tag'
    name = 'iris-backup-test-' + uuid.uuid4().hex[:8]
    owner = str(uuid.uuid4())
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    for child in ('source', 'roots', 'images', 'artifacts'):
        (state / child).mkdir()
    (state / 'source' / 'fixture').write_bytes(b'backup storage rehearsal, not production IRIS')
    (state / 'images' / 'example.bin').write_bytes(b'fixture image bytes' * 1024)
    for package in ('iris-arm64.tar', 'iris-amd64.tar', 'iris-xr.rpm'):
        (state / 'artifacts' / package).write_bytes(('fixture bytes ' + package).encode())
    for root in ('a', 'b'):
        private = tmp_path / ('root-' + root)
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(private)], check=True)
        (state / 'roots' / (root + '.pub')).write_bytes(Path(str(private) + '.pub').read_bytes())
    recovery_key = tmp_path / 'recovery-key'
    subprocess.run(['age-keygen', '-o', str(recovery_key)], check=True, capture_output=True)
    subprocess.run(['age-keygen', '-o', str(state / 'age.txt')], check=True, capture_output=True)
    recipient = subprocess.check_output(['age-keygen', '-y', str(recovery_key)], text=True).strip()
    config = dict(target='docker', instance=name, host='192.0.2.10', console_bind='127.0.0.1',
                  console_port=18080, recovery_recipient=recipient, peer_tls='required')
    compose = {'services': {}, 'volumes': {}}
    containers, volumes = [], []
    labels = ['--label', 'com.cisco.iris.installer=' + owner,
              '--label', 'com.docker.compose.project=' + name]
    try:
        for logical in ('iris-state', 'iris-config', 'iris-images', 'iris-tier-auth', 'iris-management-ca'):
            volume = name + '-' + logical
            docker('volume', 'create', *labels, volume)
            volumes.append(volume)
            compose['volumes'][logical] = {'name': volume}
            record = json.loads(docker('volume', 'inspect', volume))[0]
            path = Path(record['Mountpoint']) / 'fixture.json'
            path.write_text(json.dumps({'component': logical, 'replay_floor': 12345}))
            path.chmod(0o400)
        for service in ('iris', 'console'):
            container = name + '-' + service
            command = ['run', '-d', '--init', '--network', 'none', '--name', container, *labels,
                       '--label', 'com.docker.compose.service=' + service]
            if service == 'iris':
                for index, volume in enumerate(volumes):
                    command.extend(['-v', volume + ':/fixture/' + str(index)])
            docker(*command, image, '/bin/sh', '-c', 'sleep 3600')
            containers.append(container)
            compose['services'][service] = {'container_name': container, 'image': image}
        (state / 'compose.json').write_text(json.dumps(compose))
        (state / 'compose.env').write_text('# fixture\n')
        with Journal(state).locked() as journal:
            journal.document = {'schema': 1, 'id': owner, 'config': config,
                'source_manifest': {'fixture': hashlib.sha256((state / 'source/fixture').read_bytes()).hexdigest()},
                'root_digests': {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (state / 'roots').iterdir()},
                'completed': {'prepared': hashlib.sha256((state / 'compose.json').read_bytes()).hexdigest(),
                              'images': {image: image}, 'packages': {}}, 'state': 'PRODUCTION_REVIEW_REQUIRED'}
            journal.save()
        data_parent, identity_parent, extracted = (tmp_path / path for path in ('backups', 'identity-sets', 'extracted'))
        for path in (data_parent, identity_parent, extracted):
            path.mkdir(mode=0o700)
        yield SimpleNamespace(state=state, containers=containers, volumes=volumes,
            data=data_parent / 'set', recovery=identity_parent / 'set', extracted=extracted,
            key=recovery_key, public=state / 'backup-custody/signer.pub')
    finally:
        # Exact unique fixture resources only; no broad prune or fleet changes.
        for container in reversed(containers):
            docker('rm', '-f', container)
        for volume in reversed(volumes):
            docker('volume', 'rm', volume)


def test_real_capture_decrypt_extract_preserves_all_volumes_and_identity(deployment):
    fixture = deployment
    original = (fixture.state / 'age.txt').read_bytes()
    assert backup.create(SimpleNamespace(state_dir=fixture.state, output=fixture.data,
        recovery_output=fixture.recovery, allow_downtime=True)) == 0
    for container in fixture.containers:
        assert json.loads(docker('container', 'inspect', container))[0]['State']['Running']
    data = backup_archive.read(fixture.data, fixture.key, fixture.public,
                              destination=fixture.extracted / 'data')
    recovery = backup_archive.read(fixture.recovery, fixture.key, fixture.public,
                                  destination=fixture.extracted / 'identity')
    assert data['metadata']['backup_set_id'] == recovery['metadata']['backup_set_id']
    assert data['cutover_permitted'] is False
    assert (fixture.extracted / 'identity/service-identity').read_bytes() == original
    for logical in ('iris-state', 'iris-config', 'iris-images', 'iris-tier-auth', 'iris-management-ca'):
        record = json.loads((fixture.extracted / 'data' / ('volume-' + logical) / 'fixture.json').read_text())
        assert record == {'component': logical, 'replay_floor': 12345}
    assert (fixture.extracted / 'data/container-images').stat().st_size > 0
    assert (fixture.extracted / 'data/images/example.bin').read_bytes() == (fixture.state / 'images/example.bin').read_bytes()


def test_capture_failure_restarts_original_services(deployment, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError('simulated storage failure')
    monkeypatch.setattr(backup_archive, 'create', fail)
    with pytest.raises(OSError):
        backup.create(SimpleNamespace(state_dir=deployment.state, output=deployment.data,
            recovery_output=deployment.recovery, allow_downtime=True))
    for container in deployment.containers:
        assert json.loads(docker('container', 'inspect', container))[0]['State']['Running']
    status = json.loads((deployment.state / 'backup-operation.json').read_text())
    assert status['state'] == 'failed' and status['restart_required'] == []


def test_low_space_refused_before_downtime(deployment, monkeypatch):
    monkeypatch.setattr(backup.shutil, 'disk_usage', lambda path: SimpleNamespace(free=1))
    with pytest.raises(backup.InstallError, match='Insufficient backup space'):
        backup.create(SimpleNamespace(state_dir=deployment.state, output=deployment.data,
            recovery_output=deployment.recovery, allow_downtime=True))
    assert not (deployment.state / 'backup-operation.json').exists()
    for container in deployment.containers:
        assert json.loads(docker('container', 'inspect', container))[0]['State']['Running']


def test_external_writable_bind_of_volume_refused(deployment):
    writer = deployment.containers[0] + '-external-writer'
    mount = json.loads(docker('volume', 'inspect', deployment.volumes[0]))[0]['Mountpoint']
    image_id = json.loads(docker('container', 'inspect', deployment.containers[0]))[0]['Image']
    try:
        docker('run', '-d', '--init', '--network', 'none', '--name', writer,
               '--mount', 'type=bind,source=' + mount + ',destination=/fixture',
               image_id, '/bin/sh', '-c', 'sleep 3600')
        with pytest.raises(backup.InstallError, match='can write deployment storage'):
            backup.create(SimpleNamespace(state_dir=deployment.state, output=deployment.data,
                recovery_output=deployment.recovery, allow_downtime=True))
        assert not (deployment.state / 'backup-operation.json').exists()
    finally:
        docker('rm', '-f', writer)


def test_server_uid_can_use_readonly_control_mount_without_docker_socket(deployment):
    image = os.environ.get('IRIS_INSTALLER_DOCKER_TEST_IMAGE')
    if not image:
        pytest.skip('explicit cached Python server image required for control socket proof')
    assert json.loads(docker('image', 'inspect', image))[0]['Id'] == image
    control = deployment.state / 'control'
    control.mkdir(mode=0o750)
    control.chmod(0o750)
    os.chown(control, 0, 10001)
    worker = lifecycle_worker.Worker(deployment.state, deployment.data.parent, deployment.recovery.parent)
    endpoint = control / 'control.sock'
    server = lifecycle_worker.make_server(endpoint, worker)
    os.chown(endpoint, 0, 10001)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    script = ('import socket,json,os; s=socket.socket(socket.AF_UNIX); '
              's.connect("/run/iris-lifecycle/control.sock"); '
              's.sendall(b\'{"action":"status"}\\n\'); '
              'r=json.loads(s.makefile("rb").readline()); '
              'assert r["ok"] and r["result"]["available"]; '
              'assert not os.path.exists("/var/run/docker.sock"); print("scoped socket passed")')
    try:
        output = docker('run', '--rm', '--network', 'none', '--read-only', '--user', '10001:10001',
                        '--mount', 'type=bind,source=' + str(control) + ',destination=/run/iris-lifecycle,readonly',
                        '--entrypoint', 'python3', image, '-I', '-B', '-c', script)
        assert output.strip() == b'scoped socket passed'
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
