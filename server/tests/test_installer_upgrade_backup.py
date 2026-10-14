# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real signed/encrypted backup evidence required by an application upgrade."""

from pathlib import Path
import shutil
import subprocess
import sys
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import backup_archive, upgrade_runtime
from iris_installer.state import InstallError, atomic_write


@pytest.fixture(params=['docker', 'docker-split'])
def backups(tmp_path, request):
    for executable in ('age', 'age-keygen', 'ssh-keygen'):
        if not shutil.which(executable): pytest.skip(executable + ' is required')
    tmp_path.chmod(0o700)
    base, data, recovery = [tmp_path / name for name in ('deployment', 'data', 'recovery')]
    for path in (base, data, recovery): path.mkdir(mode=0o700)
    identity, signer = tmp_path / 'identity.age', tmp_path / 'signer'
    subprocess.run(['age-keygen', '-o', str(identity)], check=True, capture_output=True)
    recipient = subprocess.check_output(['age-keygen', '-y', str(identity)]).decode().strip()
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(signer)], check=True)
    trust = base / 'restore-custody'; trust.mkdir(mode=0o700)
    shutil.copyfile(str(signer) + '.pub', trust / 'signer.pub')
    (trust / 'signer.pub').chmod(0o644)
    payload = tmp_path / 'payload'
    atomic_write(payload, b'owned state and current producer authority')
    instance, identifier = str(uuid.uuid4()), str(uuid.uuid4())
    def create(path, scope, *, set_id=identifier, iid=instance):
        backup_archive.create({'existing': payload}, path, recipient, signer, metadata={
            'instance_id': iid, 'backup_set_id': set_id,
            'target': {'docker': 'single-docker', 'docker-split': 'split-docker'}[request.param], 'scope': scope})
    create(data / 'capture', 'managed-deployment-files')
    create(recovery / 'capture', 'identity-recovery')
    return base, {'data': str(data / 'capture'), 'identity': str(recovery / 'capture')}, {
        'instance_id': instance, 'recovery_identity': str(identity), 'target': request.param}, create


def test_upgrade_requires_genuine_decrypted_signed_pair(backups):
    base, paths, worker, _ = backups
    result = upgrade_runtime.verify_backup(base, paths, worker)
    assert result['paths'] == paths
    assert all(row['state'] == 'verified-files' for row in result['proof'].values())
    assert all(row['cutover_permitted'] is False for row in result['proof'].values())


@pytest.mark.parametrize('damage', ['wrong-instance', 'different-set', 'swapped-scope', 'changed-ciphertext', 'missing-trust'])
def test_invalid_backup_evidence_never_admits_cutover(backups, damage):
    base, paths, worker, create = backups
    if damage == 'wrong-instance': worker['instance_id'] = str(uuid.uuid4())
    elif damage == 'different-set':
        changed = Path(paths['identity']).with_name('different')
        create(changed, 'identity-recovery', set_id=str(uuid.uuid4()))
        paths['identity'] = str(changed)
    elif damage == 'swapped-scope': paths['data'], paths['identity'] = paths['identity'], paths['data']
    elif damage == 'changed-ciphertext':
        path = Path(paths['data']) / 'payload.tar.age'
        with path.open('ab') as stream: stream.write(b'changed')
    elif damage == 'missing-trust': (base / 'restore-custody/signer.pub').unlink()
    with pytest.raises((InstallError, FileNotFoundError)):
        upgrade_runtime.verify_backup(base, paths, worker)
