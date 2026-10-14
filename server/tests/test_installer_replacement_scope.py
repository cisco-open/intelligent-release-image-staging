# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Replacement is a new install; historical guards remain read-only safety."""

from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import cli, uninstall, upgrade_runtime


@pytest.mark.parametrize('verb', ['prepare', 'apply', 'recover', 'status'])
def test_no_public_inplace_upgrade_execution(verb, capsys):
    with pytest.raises(SystemExit) as stopped:
        cli.main(['upgrade', verb, '--state-dir', '/unread-state'])
    assert stopped.value.code == 2
    assert 'invalid choice' in capsys.readouterr().err


def test_supported_install_removal_and_maintenance_commands_stay_available():
    parser = cli.parser()
    assert parser.parse_args(['install']).command == 'install'
    assert parser.parse_args(['resume', '--state-dir', '/state']).command == 'resume'
    assert parser.parse_args(['uninstall', 'plan', '--state-dir', '/state']).command == 'uninstall'
    assert parser.parse_args(['maintenance', '--state-dir', '/state', 'status']).command == 'maintenance'


def test_removed_build_engines_cannot_be_imported_from_the_shipped_sdk():
    package = Path(cli.__file__).parent
    for name in ('application_upgrade.py', 'upgrade_candidate.py', 'upgrade_split.py'):
        assert not (package / name).exists()
    assert not any(hasattr(upgrade_runtime, name) for name in (
        'fence_worker', 'disable_restarts', 'capture_and_verify', 'stage_artifacts', 'refresh_worker'))


def test_uninstall_has_no_dependency_on_removed_execution_engine():
    assert 'application_upgrade' not in Path(uninstall.__file__).read_text()
    assert callable(upgrade_runtime.jobs_idle) and callable(upgrade_runtime.drain)
