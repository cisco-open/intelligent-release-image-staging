# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Normal commands must preserve the authenticated package file inventory."""

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(('command', 'module'), [('irisctl', 'cli'), ('iris-key-setup', 'key_setup')])
def test_command_disables_bytecode_before_first_installer_import(tmp_path, command, module):
    entry = tmp_path / command
    shutil.copyfile(ROOT / 'tools' / command, entry)
    package = tmp_path / 'iris_installer'
    package.mkdir()
    (package / '__init__.py').write_text('import sys\nassert sys.dont_write_bytecode\n')
    (package / (module + '.py')).write_text('from .helper import answer\ndef main():\n    return answer\n')
    (package / 'helper.py').write_text('answer = 0\n')
    before = {str(path.relative_to(tmp_path)): path.read_bytes()
              for path in tmp_path.rglob('*') if path.is_file()}
    environment = dict(os.environ)
    environment.pop('PYTHONDONTWRITEBYTECODE', None)
    environment.pop('PYTHONPYCACHEPREFIX', None)
    environment.pop('PYTHONPATH', None)
    for _ in range(2):
        subprocess.run([sys.executable, str(entry)], env=environment, cwd=tmp_path,
                       capture_output=True, check=True, timeout=10)
    after = {str(path.relative_to(tmp_path)): path.read_bytes()
             for path in tmp_path.rglob('*') if path.is_file()}
    assert after == before
