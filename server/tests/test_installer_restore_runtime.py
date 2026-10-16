# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Restore schema loading from the actual separated managed-worker layout."""
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from iris_installer import restore
from iris_installer.state import InstallError


def test_managed_worker_loads_live_source_without_checkout_pythonpath(tmp_path):
    runtime = tmp_path / 'worker-runtime' / ('a' * 64)
    runtime.mkdir(parents=True)
    shutil.copytree(ROOT / 'tools/iris_installer', runtime / 'iris_installer',
                    ignore=shutil.ignore_patterns('__pycache__'))
    source = tmp_path / 'source/server'
    source.mkdir(parents=True)
    for name in ('origin_enforcement', 'blocklist_reconciler', 'peer_endpoints',
                 'peer_policy', 'reconciler_status', 'keyed_state'):
        shutil.copyfile(ROOT / 'server' / (name + '.py'), source / (name + '.py'))
    current, archived = tmp_path / 'live', tmp_path / 'archive'
    current.mkdir(); archived.mkdir()
    # Separate process prevents pytest's server imports or PYTHONPATH from
    # hiding the missing source tree in a copied worker runtime.
    code = '''import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from iris_installer import restore
source,current,archived=map(Path,sys.argv[2:])
before=sys.path[:]
restore.state_authority(current,archived,source=source)
assert before==sys.path
import origin_enforcement
assert Path(origin_enforcement.__file__).resolve()==source/'origin_enforcement.py'
print(json.dumps({'loaded':True,'authorityPreserved':list(archived.iterdir())==[]}))
'''
    result = subprocess.run([sys.executable, '-I', '-B', '-c', code,
                             str(runtime), str(source), str(current), str(archived)],
                            capture_output=True, check=True, timeout=30, cwd=tmp_path)
    assert json.loads(result.stdout) == {'loaded': True, 'authorityPreserved': True}


@pytest.mark.parametrize('kind', ['missing', 'empty', 'symlink'])
def test_schema_unavailable_never_falls_back_to_pytest_imports(tmp_path, kind):
    source = tmp_path / 'source'
    if kind == 'empty':
        source.mkdir()
    elif kind == 'symlink':
        source.symlink_to(ROOT / 'server', target_is_directory=True)
    before = sys.path[:]
    with pytest.raises(InstallError, match='schema'):
        restore.state_authority(tmp_path, tmp_path, source=source)
    assert sys.path == before


def test_cached_schema_from_other_generation_is_refused(tmp_path, monkeypatch):
    from types import SimpleNamespace
    source = tmp_path / 'source'
    source.mkdir()
    monkeypatch.setitem(sys.modules, 'origin_enforcement',
                        SimpleNamespace(__file__=str(tmp_path / 'different.py')))
    before = sys.path[:]
    with pytest.raises(InstallError, match='different source generation'):
        restore.state_authority(tmp_path, tmp_path, source=source)
    assert sys.path == before
