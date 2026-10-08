# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Run the shipped selection model, not a copy of its former DOM renderer."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest


def test_selection_header_tracks_row_changes_without_waiting_for_a_poll():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for the client regression")
    root = Path(__file__).resolve().parents[1] / "console-ui/src"
    script = (
        f"import {{InventoryController}} from {json.dumps((root / 'inventory-controller.mjs').as_uri())};\n"
        f"import {{selectionScope}} from {json.dumps((root / 'inventory-model.mjs').as_uri())};\n"
    ) + r"""
import assert from 'node:assert/strict';
const controller = new InventoryController();
controller.update({rows: [{device_id: 'first'}, {device_id: 'second'}],
  selected: new Set(['off-page']), total: 3, matchQuery: ''});
const header = () => selectionScope(controller.snapshot()).pageLabel;
assert.equal(header(), 'Select page');
controller.toggle('first'); assert.equal(header(), 'Select page');
controller.toggle('second'); assert.equal(header(), 'Clear page selection');
controller.togglePage(); assert.deepEqual(controller.selectedIds(), ['off-page']);
controller.clearSelection(); assert.equal(header(), 'Select page');
controller.update({rows: []}); assert.equal(header(), 'Select page');
controller.togglePage(); assert.deepEqual(controller.selectedIds(), []);
controller.dispose();
"""
    result = subprocess.run([node, "--input-type=module", "-"], input=script,
                            text=True, capture_output=True, timeout=5)
    assert result.returncode == 0, result.stdout + result.stderr
