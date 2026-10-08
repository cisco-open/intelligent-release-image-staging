# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Concrete isolated Kubernetes tracker/seeder credential transaction."""

import json
from pathlib import Path
import re

from . import credential_maintenance as credentials
from .state import InstallError, regular_bytes


def verify_live_age(install, transaction, independent):
    """Prove both identities open the actual post-restart PVC ciphertexts."""
    from .topology_lifecycle import read_ciphertexts
    values = read_ciphertexts(install.run_readonly)
    if not {'secrets.json.age', 'rpc-secret.age', 'tls/key.pem.age'}.issubset(values):
        raise InstallError('Restarted Kubernetes encrypted state is incomplete')
    for value in values.values():
        if (credentials._decrypt(install, value, install.base / 'age.txt')
                != credentials._decrypt(install, value, independent)):
            raise InstallError('Restarted Kubernetes state is not independently recoverable')
    return len(values)


_CANONICAL_HASHES = '''import sys,os,json
sys.path.insert(0,'/opt/iris/server')
import rotate_seeder_announce as r
state=os.environ['IRIS_STATE']
catalog=json.load(open(os.path.join(state,'catalog.json')))
hashes=[]
for image_id,entry in catalog['images'].items():
 if not entry.get('quarantined'):
  hashes.append(r._info_hash(open(os.path.join(state,'torrents',image_id+'.torrent'),'rb').read()).lower())
if not hashes: raise RuntimeError('no published torrent targets')
print(json.dumps(sorted(hashes)))
'''


def apply_seeder(install, transaction):
    """Publish through a network-isolated, immutable, PVC-mounted helper pod.

    KubeInstall owns and fences the helper and its deny-all network policy. The
    same-ID encrypted-state recovery in rotate_seeder_announce is shared with
    Docker; only the stopped-writer runtime transport differs.
    """
    install.assert_writers_stopped()
    if 'original_seeder_fingerprint' not in transaction.record:
        config = Path(transaction.sources['volume-iris-config'])
        value = regular_bytes(config / 'secrets.json.age', credentials.MAX_SECRET)
        plain = credentials._decrypt(install, value, install.base / 'age.txt')
        if credentials._decrypt(install, value, transaction.identity) != plain:
            raise InstallError('Seeder state lacks independent recovery')
        try:
            current = json.loads(plain)['seeder']['announce_token']['value']
            if not isinstance(current, str) or not current:
                raise ValueError()
        except (KeyError, TypeError, ValueError):
            raise InstallError('Current seeder credential is unavailable') from None
        hashes = json.loads(install.maintenance_run(
            ['python3', '-I', '-B', '-c', _CANONICAL_HASHES], capture=True))
        if (not isinstance(hashes, list) or not hashes
                or any(not isinstance(value, str) or not re.fullmatch('[0-9a-f]{40}', value)
                       for value in hashes)):
            raise InstallError('Original canonical torrent identity proof is missing')
        if hashes != sorted(hashes):
            raise InstallError('Canonical torrent identity proof is not ordered')
        transaction.record.update(original_seeder_fingerprint=credentials._sha(current.encode()),
                                  original_info_hashes=hashes)
        transaction.save('applying')
    try:
        install.seeder_maintenance_start(transaction.id)
        result = install.maintenance_run(
            ['python3', '-I', '-B', '-c', credentials._SEEDER_SCRIPT, transaction.id,
             transaction.record['original_seeder_fingerprint']], capture=True, timeout=700)
        proof = json.loads(result)
        if (proof.get('credential_changed') is not True
                or proof.get('isolated_tracker_proof') is not True
                or proof.get('info_hashes') != transaction.record['original_info_hashes']):
            raise InstallError('Isolated Kubernetes seeder serving proof is unavailable')
        transaction.record['seeder_proof'] = proof
        transaction.save('applying')
    finally:
        install.seeder_maintenance_stop(transaction.id)
