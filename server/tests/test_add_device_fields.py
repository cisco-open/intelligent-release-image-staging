# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Execute the shipped form models/controllers from the Python gate.

The ES-module suite retains the management/model/late-body behavior checks from
the former extracted app.js harness and adds wire, credential and mutation races.
Browser suites separately check actual labels, visibility, focus and controls.
"""
from pathlib import Path
import shutil
import subprocess

import pytest


def test_device_and_credential_form_regressions():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for device form regressions")
    tests = Path(__file__).resolve().parents[1] / "console-ui/tests/device-forms.test.mjs"
    result = subprocess.run([node, "--test", "--test-reporter=tap", str(tests)], text=True,
                            capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "# fail 0" in result.stdout
