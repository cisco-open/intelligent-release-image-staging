# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Keep the shipped Inventory controller regressions in the Python test gate.

The former extracted app.js selection tests now import the actual ES modules.
The same cases also run in npm test; no React build or browser is needed here.
"""
from pathlib import Path
import shutil
import subprocess

import pytest


def test_inventory_controller_and_selection_regressions():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for Inventory client regressions")
    tests = Path(__file__).resolve().parents[1] / "console-ui/tests/inventory.test.mjs"
    result = subprocess.run([node, "--test", "--test-reporter=tap", str(tests)], text=True,
                            capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "# fail 0" in result.stdout
