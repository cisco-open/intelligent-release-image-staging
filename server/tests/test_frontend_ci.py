# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""The required test workflow must build and exercise the public React UI."""
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_ci_includes_xr_https_and_api_exercise_regressions():
    workflow = yaml.safe_load((ROOT / '.github/workflows/tests.yml').read_text())
    steps = workflow['jobs']['test']['steps']
    command = next(step['run'] for step in steps if step.get('name') == 'pytest')
    documented = (ROOT / 'TESTING.md').read_text()
    for suite in ('device/xr/tests/', 'tools/test_api_exercise.py'):
        assert suite in command
        assert suite in documented


def test_ci_runs_locked_frontend_build_and_mocked_chromium():
    workflow = yaml.safe_load((ROOT / '.github/workflows/tests.yml').read_text())
    job = workflow['jobs']['frontend']
    assert job['timeout-minutes'] <= 10
    assert job['defaults']['run']['working-directory'] == 'server/console-ui'
    runs = [step['run'] for step in job['steps'] if 'run' in step]
    assert runs == ['npm ci --no-audit --no-fund', 'npm test',
                    'npx --no-install playwright install --with-deps chromium',
                    'npm run test:browser', 'npm run test:swagger']
    package = json.loads((ROOT / 'server/console-ui/package.json').read_text())
    assert package['scripts']['test:browser'] == 'node tests/browser-smoke.mjs'
    assert package['scripts']['test:swagger'] == 'node tests/swagger-smoke.mjs'
    lock = json.loads((ROOT / 'server/console-ui/package-lock.json').read_text())
    assert lock['packages']['node_modules/playwright']['version'] == package['devDependencies']['playwright']
    assert lock['packages']['node_modules/playwright']['dev'] is True
