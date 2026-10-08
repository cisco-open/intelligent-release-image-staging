# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Execute shipped Inventory selection code with controlled page/read races."""
import json
from pathlib import Path
import re
import shutil
import subprocess

import pytest


_APP = Path(__file__).resolve().parents[1] / "webroot/app.js"


def _run(case):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for selection regressions")
    source = _APP.read_text()
    functions = []
    for name in ("updateSelBar", "cancelSelectAllMatching", "selectAllMatchingDevices",
                 "toggleDeviceRow", "claimSelection"):
        match = re.search(r"^  (?:async )?function " + name + r"\([^\n]*\) \{.*?^  \}",
                          source, re.MULTILINE | re.DOTALL)
        assert match, name
        functions.append(match.group())
    program = r'''
const assert = require('node:assert/strict');
const elements = new Map();
const element = id => {
  if (!elements.has(id)) elements.set(id, {textContent: '', hidden: false, disabled: false, classList: {toggle(name, value) { this[name] = value; }}});
  return elements.get(id);
};
const makeRow = id => ({dataset: {id}, classList: {toggle() {}}, setAttribute() {}});
let rows = [makeRow('B')], query = 'q=b';
const document = {getElementById: element, querySelectorAll: () => rows};
let SELECTED = Object.assign(Object.create(null), {A: true}), devTotal = 1, openMenuPanel = null;
let deviceSelectionQuery = query, deviceMatchIds = ['B'], selectAllMatchingBusy = false;
let selectAllMatchingRun = null, bulkBusy = false;
const BULK_MODALS = [], devStatus = element('dev-status');
const requests = [];
function closeModal() {}
function closeMenus() {}
function selectedIds() { return Object.keys(SELECTED); }
function setBulkBusy(value) { bulkBusy = value; }
function deviceFilterState() { return query; }
function deviceFilterQuery(value) { return value; }
const pending = () => { let resolve; const promise = new Promise(yes => { resolve = yes; }); return {promise, resolve}; };
const turn = () => new Promise(resolve => setImmediate(resolve));
const response = (ids, total = ids.length, offset = 0, revision = 1) => ({ok: true, json: async () => ({total, offset, revision,
  devices: ids.map(device_id => ({device_id}))})});
let read = async () => response(['B']);
async function fetch(url, options) {
  assert.equal(options?.method, undefined, 'Selection does not submit a device action');
  requests.push([url, options]); return read(url, options);
}
''' + "\n".join(functions) + "\n(async () => {\n" + case + r'''
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
    result = subprocess.run([node, "-"], input=program, text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("selected", [{"A": True}, {"A": True, "C": True}])
def test_equal_or_larger_selected_count_does_not_prove_matching_ids(selected):
    _run("SELECTED = " + json.dumps(selected) + r''';
updateSelBar();
assert.doesNotMatch(element('sel-scope-text').textContent, /All .*matching/);
assert.match(element('sel-scope-text').textContent, /selected outside this filter/);
assert.equal(element('sel-scope-all').hidden, false);
assert.equal(element('mark-all').textContent, 'Select page');
''')


def test_complete_ids_prove_membership_and_expose_extra_selections():
    _run(r'''
SELECTED.B = true;
updateSelBar();
assert.equal(element('sel-scope-text').textContent, '· All 1 matching devices selected; 1 selected outside this filter');
assert.equal(element('sel-scope-all').hidden, true);
delete SELECTED.A; updateSelBar();
assert.equal(element('sel-scope-text').textContent, '· All 1 matching devices selected');
deviceMatchIds = null; devTotal = 2; SELECTED.C = true;
updateSelBar();
assert.equal(element('sel-scope-all').hidden, false, 'Partial page and equal counts are not complete coverage');
assert.equal(element('sel-scope-text').textContent, '· 1 selected outside this page');
''')


def test_pending_or_failed_filter_cannot_offer_stale_scope():
    _run(r'''
for (const invalid of [null, 'q=other']) {
  deviceSelectionQuery = invalid; updateSelBar();
  assert.equal(element('sel-scope-all').hidden, true);
  assert.match(element('sel-scope-text').textContent, /matches are unconfirmed/);
  await selectAllMatchingDevices();
}
assert.equal(requests.length, 0);
deviceSelectionQuery = query; devTotal = 0; deviceMatchIds = [];
updateSelBar();
assert.equal(element('sel-scope-all').hidden, true);
assert.match(element('sel-scope-text').textContent, /1 selected outside this filter/);
''')


def test_select_all_applies_complete_pages_atomically_and_retains_previous_ids():
    _run(r'''
const first = Array.from({length: 1000}, (_, i) => 'd' + i), held = pending();
devTotal = 1001; deviceMatchIds = null;
read = async url => url.endsWith('offset=0') ? response(first, 1001) : held.promise;
const selecting = selectAllMatchingDevices(); await turn();
assert.deepEqual(selectedIds(), ['A'], 'No partial page added before the last response');
assert.equal(element('sel-scope-all').disabled, true);
await selectAllMatchingDevices(); assert.equal(requests.length, 2, 'Duplicate clicks do not start another walk');
held.resolve(response(['d1000'], 1001, 1000)); await selecting;
assert.equal(selectedIds().length, 1002); assert.equal(SELECTED.A, true);
assert.equal(deviceMatchIds.length, 1001);
assert.match(element('sel-scope-text').textContent, /All 1001 matching devices selected; 1 selected outside this filter/);
assert.equal(selectAllMatchingBusy, false);
assert.equal(devStatus.classList.err, false); assert.equal(devStatus.classList.muted, true);
assert.ok(requests.every(([url]) => url.includes('q=b&limit=1000')));
''')


@pytest.mark.parametrize("failure", ["http", "network", "json", "total", "revision", "invalid-revision", "duplicate", "empty", "offset", "invalid-id"])
def test_later_page_failure_leaves_previous_selection_unchanged(failure):
    _run("const failure = " + json.dumps(failure) + r''';
const first = Array.from({length: 1000}, (_, i) => 'd' + i);
devTotal = 1001; deviceMatchIds = null;
read = async url => {
  if (url.endsWith('offset=0')) return response(first, 1001);
  if (failure === 'network') throw new Error('lost');
  if (failure === 'http') return {ok: false, status: 503};
  if (failure === 'json') return {ok: true, json() { throw new Error('invalid JSON'); }};
  if (failure === 'total') return response(['new'], 1002, 1000);
  if (failure === 'revision') return response(['new'], 1001, 1000, 2);
  if (failure === 'invalid-revision') return response(['new'], 1001, 1000, '1');
  if (failure === 'duplicate') return response(['d0'], 1001, 1000);
  if (failure === 'empty') return response([], 1001, 1000);
  if (failure === 'offset') return response(['new'], 1001, 0);
  return response([null], 1001, 1000);
};
await selectAllMatchingDevices();
assert.deepEqual(selectedIds(), ['A']); assert.equal(deviceMatchIds, null);
assert.match(devStatus.textContent, /selection is unchanged/);
assert.equal(devStatus.classList.err, true); assert.equal(devStatus.classList.muted, false);
assert.equal(selectAllMatchingBusy, false); assert.equal(element('sel-scope-all').disabled, false);
''')


@pytest.mark.parametrize("delay", ["headers", "body"])
def test_cancelled_read_cannot_replace_a_new_walk_or_expand_a_changed_selection(delay):
    _run("const delay = " + json.dumps(delay) + r''';
const held = pending();
read = async () => delay === 'headers' ? held.promise : {ok: true, json: () => held.promise};
const old = selectAllMatchingDevices(); await turn();
cancelSelectAllMatching(); query = 'q=new'; deviceSelectionQuery = query;
const fresh = pending(); read = () => fresh.promise;
const newest = selectAllMatchingDevices();
const stale = {devices: [{device_id: 'stale'}], total: 1, offset: 0};
held.resolve(delay === 'headers' ? {ok: true, json: async () => stale} : stale); await old;
assert.equal(selectAllMatchingBusy, true, 'An old finally must not unlock the new walk');
assert.equal(SELECTED.stale, undefined);
fresh.resolve(response(['new'])); await newest;
assert.deepEqual(selectedIds(), ['A', 'new']);
''')


def test_row_change_or_bulk_action_cancels_an_outstanding_expansion():
    _run(r'''
for (const action of ['row', 'bulk']) {
  const held = pending(); read = () => held.promise;
  const selecting = selectAllMatchingDevices(); await turn();
  if (action === 'row') toggleDeviceRow(makeRow('B'));
  else assert.deepEqual(claimSelection(), ['A', 'B']);
  assert.equal(requests.at(-1)[1].signal.aborted, true);
  held.resolve(response(['late'])); await selecting;
  assert.equal(SELECTED.late, undefined);
}
await selectAllMatchingDevices();
assert.equal(requests.length, 2, 'Bulk lock prevents a new selection read');
''')


def test_changed_filter_without_cancellation_still_rejects_a_late_body():
    _run(r'''
const held = pending(); read = async () => ({ok: true, json: () => held.promise});
const selecting = selectAllMatchingDevices(); await turn();
query = 'q=another';
held.resolve({total: 1, offset: 0, devices: [{device_id: 'stale'}]}); await selecting;
assert.deepEqual(selectedIds(), ['A']);
assert.equal(selectAllMatchingBusy, false);
assert.equal(element('sel-scope-all').hidden, true);
''')


def test_prototype_named_ids_are_selected_as_data():
    _run(r'''
devTotal = 2; read = async () => response(['__proto__', 'constructor']);
await selectAllMatchingDevices();
assert.deepEqual(selectedIds().sort(), ['A', '__proto__', 'constructor']);
assert.equal(Object.getPrototypeOf(SELECTED), null);
assert.equal(element('sel-scope-text').textContent, '· All 2 matching devices selected; 1 selected outside this filter');
''')
