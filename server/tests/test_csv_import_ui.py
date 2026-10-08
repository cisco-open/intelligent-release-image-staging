# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Execute the shipped CSV and Inventory action controller without fleet writes."""
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_csv_and_inventory_action_controller_regressions():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for the shipped browser controller")
    result = subprocess.run([node, "--test", str(ROOT / "console-ui/tests/inventory-actions.test.mjs")],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "# fail 0" in result.stdout


def test_csv_dom_has_one_react_owner_and_same_file_can_be_selected_again():
    source = (ROOT / "console-ui/src/inventory-actions.jsx").read_text()
    old = (ROOT / "webroot/app.js").read_text()
    html = (ROOT / "webroot/index.html").read_text()
    for identifier in ("csv-file", "csv-import-status"):
        assert 'id="%s"' % identifier in source
        assert 'id="%s"' % identifier not in html
        assert "getElementById('%s')" % identifier not in old
    assert "event.target.value = ''; controller.importFile(selected)" in source
    assert "inventoryActions.chooseFile()" in old
    assert "inventoryActions.download(url, filename)" in old
