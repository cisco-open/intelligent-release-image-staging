# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Opt-in real local managed unit, interrupted capture and surviving writer.

Only a uniquely owned unit and the existing explicit Docker test fixture are
created. No network/image pull or product deployment is used. The service,
SDK/runtime pins, cgroup, encryption, worker request and recovery are real.
"""

import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
from types import SimpleNamespace
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import backup_capture, managed_worker as managed
from test_backup_docker import deployment, docker


def call(state, request):
    directory = os.open(state / 'control', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect('/proc/self/fd/' + str(directory) + '/control.sock')
            connection.sendall(json.dumps(request).encode() + b'\n')
            value = connection.makefile('rb').readline(4 * 1024 * 1024)
        response = json.loads(value)
        assert response['ok'], response
        return response['result']
    finally:
        os.close(directory)


def until(callback, *, timeout=30):
    deadline = time.monotonic() + timeout
    while True:
        try:
            value = callback()
            if value:
                return value
        except (FileNotFoundError, ConnectionRefusedError, ConnectionResetError, json.JSONDecodeError):
            pass
        if time.monotonic() >= deadline:
            pytest.fail('bounded managed capture condition did not settle')
        time.sleep(0.025)


@pytest.mark.skipif(os.environ.get('IRIS_CAPTURE_SYSTEMD_TEST') != '1', reason='explicit local systemd test opt-in required')
def test_actual_worker_interruption_writer_refusal_and_same_job_recovery(deployment, tmp_path):
    fixture = deployment
    assert subprocess.check_output(['docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'], text=True).strip() == 'unix:///var/run/docker.sock'
    document = json.loads((fixture.state / 'installation.json').read_bytes())
    unit = 'iris-lifecycle-' + document['id'] + '.service'
    unit_path = managed.UNIT_DIRECTORY / unit
    assert not unit_path.exists() and not unit_path.is_symlink()
    backup_root, recovery_root = [tmp_path / name for name in ('managed-data', 'managed-recovery')]
    for path in (backup_root, recovery_root):
        path.mkdir(mode=0o700)
    # A sparse, inert fixture file makes the actual encrypted capture long
    # enough to interrupt after the clean-stop marker, without downloading data.
    volume = json.loads(docker('volume', 'inspect', fixture.volumes[0]))[0]
    source = Path(volume['Mountpoint']) / 'interruption-fixture'
    with source.open('xb') as stream:
        stream.truncate(512 * 1024 * 1024)
    source.chmod(0o600)
    writer = None
    expected_unit = None
    try:
        managed.setup(SimpleNamespace(state_dir=fixture.state, backup_root=backup_root, recovery_root=recovery_root))
        record = managed._load(fixture.state)
        expected_unit = managed.unit_bytes(fixture.state, record)
        assert unit_path.read_bytes() == expected_unit
        request_id = str(uuid.uuid4())
        assert call(fixture.state, {'action': 'backup', 'request_id': request_id, 'allow_downtime': True}) == {'job_id': request_id}
        intent_path = fixture.state / 'backup-captures' / (request_id + '.json')
        def capturing():
            intent = json.loads(intent_path.read_bytes())
            return intent if intent['phase'] == 'capturing' else None
        intent = until(capturing)
        assert intent['clean_stop'] is True
        original = intent['worker']['process']
        assert backup_capture._process(original['pid']) == original
        assert intent['worker']['unit'] == unit and intent['worker']['cgroup']['inode'] > 0
        subprocess.run(['systemctl', 'kill', '--kill-whom=main', '--signal=SIGKILL', unit], check=True, capture_output=True)
        def recovered_worker():
            status = call(fixture.state, {'action': 'status'})
            job = next(item for item in status['jobs'] if item['id'] == request_id)
            assert status['can_recover_backup'] is True
            if job['state'] == 'recovery-required':
                assert status['retention']['busy'] is True
                assert status['retention']['recoverable_job_id'] == request_id
            assert 'capture_authority_started' not in job and 'capture_recovery_requested' not in job
            return job if job['state'] == 'recovery-required' else None
        job = until(recovered_worker, timeout=30)
        assert backup_capture._process(original['pid']) != original
        assert job['backup_id'] == intent['backup_id']
        group = subprocess.check_output(['systemctl', 'show', unit, '--property=ControlGroup', '--value'], text=True).strip()
        assert group.startswith('/system.slice/iris-lifecycle-') and group.endswith('.service')
        # Reproduce a surviving writer in the ACTUAL service cgroup. It writes
        # only this test's private stage; its exact PID/birth is captured before
        # placement and checked before termination. Unit bytes remain unchanged.
        stage = tmp_path / 'surviving-test-writer'
        code = 'import pathlib,time,sys\np=pathlib.Path(sys.argv[1])\nwhile True:\n with p.open("ab") as s:s.write(b"owned fixture\\n")\n time.sleep(.05)\n'
        writer = subprocess.Popen(['/usr/bin/python3', '-c', code, str(stage)])
        writer_identity = backup_capture._process(writer.pid)
        (Path('/sys/fs/cgroup') / group.lstrip('/') / 'cgroup.procs').write_text(str(writer.pid))
        until(lambda: stage.exists() and stage.stat().st_size > 0)
        recovery_request = {'action': 'recover-backup', 'request_id': request_id,
                            'backup_id': intent['backup_id'], 'allow_downtime': True}
        assert call(fixture.state, recovery_request) == {'job_id': request_id}
        refused = until(recovered_worker)
        assert 'capture writer is still active' in refused['detail']
        assert all(not json.loads(docker('inspect', container))[0]['State']['Running'] for container in fixture.containers)
        assert backup_capture._process(writer.pid) == writer_identity
        writer.terminate()
        writer.wait(timeout=5)
        assert backup_capture._process(writer.pid) is None
        writer = None
        assert call(fixture.state, recovery_request) == {'job_id': request_id}
        def settled():
            current = next(item for item in call(fixture.state, {'action': 'status'})['jobs'] if item['id'] == request_id)
            return current if current['state'] in ('captured', 'failed') else None
        settled_job = until(settled)
        assert settled_job['state'] == 'failed'
        assert settled_job['proof']['recaptured'] is False
        assert settled_job['proof']['services_healthy'] is True
        assert all(json.loads(docker('inspect', container))[0]['State']['Running'] for container in fixture.containers)
        final_intent = json.loads(intent_path.read_bytes())
        assert final_intent['set_id'] == intent['set_id'] and final_intent['phase'] == 'settled-failed'
        assert len(final_intent['publications']) < 2
        observed_dirs = {kind: list(Path(target['path']).parent.iterdir()) for kind, target in final_intent['destinations'].items()}
        assert call(fixture.state, recovery_request) == {'job_id': request_id}
        assert next(item for item in call(fixture.state, {'action': 'status'})['jobs'] if item['id'] == request_id) == settled_job
        assert {kind: list(Path(target['path']).parent.iterdir()) for kind, target in final_intent['destinations'].items()} == observed_dirs
        tracked_stages = {}
        for stage_record in final_intent['stages'].values():
            retained = Path(stage_record['path'])
            if retained.exists():
                tracked_stages[str(retained)] = (retained.stat().st_dev, retained.stat().st_ino)
        fresh_id = str(uuid.uuid4())
        assert call(fixture.state, {'action': 'backup', 'request_id': fresh_id, 'allow_downtime': True}) == {'job_id': fresh_id}
        def fresh_completed():
            current = next(item for item in call(fixture.state, {'action': 'status'})['jobs'] if item['id'] == fresh_id)
            return current if current['state'] != 'running' else None
        fresh = until(fresh_completed, timeout=60)
        assert fresh['state'] == 'captured', fresh
        assert fresh['backup_id'] != intent['backup_id']
        assert json.loads(intent_path.read_bytes())['set_id'] == intent['set_id']
        assert all((Path(path).stat().st_dev, Path(path).stat().st_ino) == identity for path, identity in tracked_stages.items())
        assert all(json.loads(docker('inspect', container))[0]['State']['Running'] for container in fixture.containers)
    finally:
        if writer is not None:
            writer.terminate()
            writer.wait(timeout=5)
        if unit_path.exists():
            assert expected_unit is not None and unit_path.read_bytes() == expected_unit
            subprocess.run(['systemctl', 'disable', '--now', unit], check=True, capture_output=True, timeout=30)
            assert subprocess.check_output(['systemctl', 'show', unit, '--property=MainPID', '--value'], text=True).strip() == '0'
            unit_path.unlink()
            subprocess.run(['systemctl', 'daemon-reload'], check=True, capture_output=True)
            subprocess.run(['systemctl', 'reset-failed', unit], check=False, capture_output=True)
        assert not unit_path.exists()


@pytest.mark.skipif(os.environ.get('IRIS_CAPTURE_SYSTEMD_TEST') != '1', reason='explicit local systemd test opt-in required')
def test_read_worker_sigkill_leaves_no_archive_scratch_and_allows_fresh_capture(deployment, tmp_path):
    """Actual unit, crypto, original request and later capture; no journal injection."""
    fixture = deployment
    assert subprocess.check_output(['docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'], text=True).strip() == 'unix:///var/run/docker.sock'
    document = json.loads((fixture.state / 'installation.json').read_bytes())
    unit = 'iris-lifecycle-' + document['id'] + '.service'
    unit_path = managed.UNIT_DIRECTORY / unit
    assert not unit_path.exists() and not unit_path.is_symlink()
    roots = [tmp_path / name for name in ('read-data', 'read-recovery')]
    for path in roots:
        path.mkdir(mode=0o700)
    volume = json.loads(docker('volume', 'inspect', fixture.volumes[0]))[0]
    with (Path(volume['Mountpoint']) / 'read-interruption-fixture').open('xb') as stream:
        stream.truncate(256 * 1024 * 1024)
    expected_unit, handles = None, []

    def finished(request_id):
        row = next(item for item in call(fixture.state, {'action': 'status'})['jobs'] if item['id'] == request_id)
        return row if row['state'] != 'running' else None

    def children(path):
        return {child.name: (child.stat().st_dev, child.stat().st_ino, child.stat().st_mode)
                for child in path.iterdir()}

    try:
        managed.setup(SimpleNamespace(state_dir=fixture.state, backup_root=roots[0],
            recovery_root=roots[1], recovery_identity=fixture.key))
        record = managed._load(fixture.state)
        expected_unit = managed.unit_bytes(fixture.state, record)
        assert unit_path.read_bytes() == expected_unit
        assert call(fixture.state, {'action': 'status'})['can_verify'] is True
        capture_id = str(uuid.uuid4())
        assert call(fixture.state, {'action': 'backup', 'request_id': capture_id, 'allow_downtime': True}) == {'job_id': capture_id}
        captured = until(lambda: finished(capture_id), timeout=90)
        assert captured['state'] == 'captured', captured
        parents = [Path(record['storage'][kind]['directory']) for kind in ('backup', 'recovery')]
        before = [children(path) for path in parents]
        request_id = str(uuid.uuid4())
        original = int(subprocess.check_output(['systemctl', 'show', unit, '--property=MainPID', '--value'], text=True))
        original_identity = backup_capture._process(original)
        main_fd = os.pidfd_open(original)
        handles.append((main_fd, original_identity))
        assert call(fixture.state, {'action': 'verify', 'request_id': request_id,
                                   'backup_id': captured['backup_id']}) == {'job_id': request_id}

        def freeze_decryptor():
            assert backup_capture._process(original) == original_identity
            candidates = set()
            for task in (Path('/proc') / str(original) / 'task').iterdir():
                try:
                    candidates.update(map(int, (task / 'children').read_text().split()))
                except FileNotFoundError:
                    pass
            for pid in candidates:
                try:
                    command = (Path('/proc') / str(pid) / 'cmdline').read_bytes()
                except FileNotFoundError:
                    continue
                if command != b'age\0-d\0-i\0' + record['recovery_identity'].encode() + b'\0':
                    continue
                identity = backup_capture._process(pid)
                if identity is None:
                    continue
                fd = os.pidfd_open(pid)
                if backup_capture._process(pid) != identity:
                    os.close(fd)
                    continue
                handles.append((fd, identity))
                signal.pidfd_send_signal(fd, signal.SIGSTOP)
                signal.pidfd_send_signal(main_fd, signal.SIGSTOP)
                return identity
            return None

        decryptor = until(freeze_decryptor, timeout=15)
        # The observed REAL decryptor and worker are now held, so the original
        # admitted job cannot settle normally or execute finally cleanup.
        raw_job = next(row for row in json.loads((fixture.state / 'lifecycle-jobs.json').read_bytes()) if row['id'] == request_id)
        assert raw_job['action'] == 'verify' and raw_job['state'] == 'running'
        assert backup_capture._process(original) == original_identity
        assert backup_capture._process(decryptor['pid']) == decryptor
        assert [children(path) for path in parents] == before
        assert os.readlink(Path('/proc') / str(decryptor['pid']) / 'fd/0').startswith('pipe:')
        assert os.readlink(Path('/proc') / str(decryptor['pid']) / 'fd/1').startswith('pipe:')
        signal.pidfd_send_signal(handles[-1][0], signal.SIGKILL)
        signal.pidfd_send_signal(main_fd, signal.SIGKILL)
        failed = until(lambda: finished(request_id), timeout=30)
        assert failed['state'] == 'failed' and failed['id'] == request_id
        assert failed['backup_id'] == captured['backup_id']
        assert backup_capture._process(original) != original_identity
        until(lambda: backup_capture._process(decryptor['pid']) != decryptor)
        assert unit_path.read_bytes() == expected_unit
        assert [children(path) for path in parents] == before
        assert not any(path.name.startswith(('.iris-verify-', '.iris-restore-'))
                       for parent in parents for path in parent.iterdir())
        status = call(fixture.state, {'action': 'status'})
        assert status['retention']['inventory_available'] is True
        assert status['retention']['storage_problem'] is None
        assert next(row for row in status['retention']['jobs'] if row['id'] == request_id)['retire_allowed'] is True
        assert all(json.loads(docker('inspect', container))[0]['State']['Running'] for container in fixture.containers)
        # No unlink/rmtree/retention helper has run. A NEW real managed capture
        # must therefore pass the normal inventory/capacity/service admission.
        fresh = str(uuid.uuid4())
        assert call(fixture.state, {'action': 'backup', 'request_id': fresh, 'allow_downtime': True}) == {'job_id': fresh}
        completed = until(lambda: finished(fresh), timeout=90)
        assert completed['state'] == 'captured' and completed['backup_id'] != captured['backup_id']
        for parent, saved in zip(parents, before):
            assert all(children(parent)[name] == identity for name, identity in saved.items())
            assert not any(path.name.startswith(('.iris-verify-', '.iris-restore-')) for path in parent.iterdir())
        assert all(json.loads(docker('inspect', container))[0]['State']['Running'] for container in fixture.containers)
    finally:
        # Emergency cleanup is exact and explicit. It occurs AFTER assertions;
        # no workspace deletion can disguise archive-root pollution as a pass.
        for fd, identity in reversed(handles):
            if backup_capture._process(identity['pid']) == identity:
                signal.pidfd_send_signal(fd, signal.SIGCONT)
            os.close(fd)
        if unit_path.exists():
            assert expected_unit is not None and unit_path.read_bytes() == expected_unit
            subprocess.run(['systemctl', 'disable', '--now', unit], check=True, capture_output=True, timeout=30)
            assert subprocess.check_output(['systemctl', 'show', unit, '--property=MainPID', '--value'], text=True).strip() == '0'
            unit_path.unlink()
            subprocess.run(['systemctl', 'daemon-reload'], check=True, capture_output=True)
            subprocess.run(['systemctl', 'reset-failed', unit], check=False, capture_output=True)
        assert not unit_path.exists()
