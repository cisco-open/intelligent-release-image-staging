# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Run the real selection-bar code against page-local row selection."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest


def test_selection_header_tracks_row_changes_without_waiting_for_a_poll():
    if not shutil.which("node"):
        pytest.skip("Node is required for the browser-client regression")
    source = (Path(__file__).resolve().parents[1] / "webroot/app.js").read_text()
    function = "function updateSelBar() {" + source.split(
        "function updateSelBar() {", 1)[1].split(
        "  function toggleDeviceRow(", 1)[0]
    script = r'''
const assert = require('node:assert/strict');
const elements = new Map();
const rows = ['first', 'second'].map(id => ({dataset: {id},
  classList: {toggle(name, value) {this[name] = value;}},
  setAttribute(name, value) {this[name] = value;}}));
const document = {
  getElementById(id) {
    if (!elements.has(id)) elements.set(id, {});
    return elements.get(id);
  },
  querySelectorAll(selector) {
    assert.equal(selector, '#dev-rows tr[data-id]');
    return rows;
  }
};
let SELECTED = {'off-page': true}, devTotal = 3, openMenuPanel = null;
const BULK_MODALS = [];
function closeModal() {}
function closeMenus() {}
eval(FUNCTION);
const header = document.getElementById('mark-all');
updateSelBar();
assert.equal(header.textContent, 'Select page', 'Off-page selection does not select this page');
assert.equal(rows[0]['aria-selected'], 'false');
SELECTED.first = true;
updateSelBar();
assert.equal(header.textContent, 'Select page');
assert.equal(rows[0]['aria-selected'], 'true');
assert.equal(rows[0].classList.sel, true);
assert.equal(rows[1]['aria-selected'], 'false');
SELECTED.second = true;
updateSelBar();
assert.equal(header.textContent, 'Clear page selection');
SELECTED = {};
updateSelBar();
assert.equal(header.textContent, 'Select page');
assert.equal(rows[0]['aria-selected'], 'false');
rows.length = 0;
updateSelBar();
assert.equal(header.disabled, true, 'An empty table cannot be selected');
'''.replace("FUNCTION", json.dumps(function))
    result = subprocess.run(["node", "-e", script], text=True,
                            capture_output=True, timeout=5)
    assert result.returncode == 0, result.stdout + result.stderr
