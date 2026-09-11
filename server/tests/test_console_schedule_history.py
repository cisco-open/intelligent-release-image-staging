# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Exercise the actual schedule-history reader and table renderer."""
import json
from pathlib import Path
import re
import shutil
import subprocess

import pytest


def _render(mode, count=1):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for Console schedule tests")
    source = (Path(__file__).resolve().parents[1] / "webroot/app.js").read_text()
    functions = []
    for name in ("latestOccurrence", "renderSchedules"):
        found = re.search(r"^  async function " + name + r"\([^\n]*\) \{.*?^  \}",
                          source, re.MULTILINE | re.DOTALL)
        assert found, name
        functions.append(found.group(0))
    program = r'''
const mode = MODE;
const count = COUNT;
const rows = {innerHTML: ''};
const document = {getElementById: () => rows, querySelectorAll: () => []};
var SCHEDULES = [], SCHED_HISTORY_ROWS = 25, schedRefreshGeneration = 0;
var schedStatus = {};
function esc(s) { return String(s); }
function scheduleTargetSummary() { return ''; }
function scheduleNextFireText() { return ''; }
function scheduleDeltaText() { return ''; }
function scheduleWaveText() { return ''; }
function scheduleCreatorText() { return ''; }
const schedules = Array.from({length: count}, (_,i) => ({
  id: i === 25 ? 'constructor' : 's' + i, kind: 'assign',
  state: 'pending', creator_exists: true
}));
const historyReads = [];
async function fetch(url) {
  if (url === '/api/v1/schedules') return {ok: true, json: async () => ({schedules})};
  historyReads.push(url);
  if (mode === 'network') throw new Error('offline');
  if (!url.includes('offset=')) {
    if (mode === 'probe-fails') return {ok: false, status: 503};
    return {ok: true, json: async () => ({total: mode === 'empty' ? 0 : 1})};
  }
  if (mode === 'page-fails') return {ok: false, status: 503};
  return {ok: true, json: async () => ({occurrences:
    mode === 'missing-row' ? [] : [{state: 'completed'}]})};
}
'''.replace("MODE", json.dumps(mode)).replace("COUNT", str(count))
    program += "\n".join(functions)
    program += r'''
(async () => {
  await renderSchedules();
  process.stdout.write(JSON.stringify({html: rows.innerHTML, historyReads}));
})().catch(error => {console.error(error); process.exit(1);});
'''
    result = subprocess.run([node, "-"], input=program, text=True,
                            capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_history_cap_keeps_unread_schedules_visible_without_claiming_no_runs():
    result = _render("completed", 26)
    assert len(result["historyReads"]) == 50
    assert result["html"].count("<tr ") == 26
    last = result["html"].split('<tr data-id="constructor">')[1]
    assert "run history unavailable" in last
    assert "no run yet" not in last
    assert result["html"].count("<td>completed</td>") == 25


@pytest.mark.parametrize("mode", ["probe-fails", "page-fails", "network", "missing-row"])
def test_failed_or_incomplete_history_is_unavailable(mode):
    result = _render(mode)
    assert "run history unavailable" in result["html"]
    assert "no run yet" not in result["html"]


def test_confirmed_zero_history_still_reports_no_run_yet():
    result = _render("empty")
    assert "no run yet" in result["html"]
    assert "run history unavailable" not in result["html"]
    assert len(result["historyReads"]) == 1


def test_lost_creation_response_does_not_claim_the_schedule_was_not_created():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for Console schedule tests")
    source = (Path(__file__).resolve().parents[1] / "webroot/app.js").read_text()
    start = source.index("  document.getElementById('create-schedule').addEventListener")
    end = source.index("\n  });", start) + len("\n  });")
    program = r'''
const elements = new Map();
function el(id) {
  if (!elements.has(id)) elements.set(id, {value: '', listeners: {},
    textContent: '', addEventListener(event, fn) {this.listeners[event] = fn;}});
  return elements.get(id);
}
const document = {getElementById: el};
const values = {'sched-modal-id': 'nightly', 'sched-modal-scope': 'selection',
  'sched-modal-when': 'once', 'sched-modal-time': '02:30',
  'sched-modal-at': '2026-09-12T02:30', 'sched-modal-kind': 'assign',
  'sched-modal-mode': 'merge', 'sched-modal-max': '20',
  'sched-modal-weekday': '6', 'sched-modal-tz': 'UTC', 'sched-modal-window': '60'};
for (const [key,value] of Object.entries(values)) el(key).value = value;
el('sched-modal-images').selectedOptions = [{value: 'image-a'}];
var bulkBusy = false, accepted = null;
function claimSelection() {bulkBusy = true; return ['edge-1'];}
function setBulkBusy(value) {bulkBusy = value;}
function deviceFilterState() {return {};}
function scheduleTargetFromFilters(filters, ids) {return {device_ids: ids};}
function scheduleDefinitionFromForm(values) {return values;}
async function jpost(url, body) {
  accepted = body.id; // model acceptance before losing the response
  throw new Error('response lost');
}
'''
    program += source[start:end]
    program += r'''
(async () => {
  await el('create-schedule').listeners.click();
  process.stdout.write(JSON.stringify({accepted, bulkBusy,
    message: el('sched-modal-msg').textContent}));
})().catch(error => {console.error(error); process.exit(1);});
'''
    result = subprocess.run([node, "-"], input=program, text=True,
                            capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["accepted"] == "nightly"
    assert output["bulkBusy"] is False
    assert "not created" not in output["message"].lower()
    assert "may have been created" in output["message"].lower()
    assert "refresh" in output["message"].lower()
