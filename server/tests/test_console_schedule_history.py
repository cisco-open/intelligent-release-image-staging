# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Run the shipped React schedule controller's history and uncertain writes."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest


def _render(mode, count=1):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for Console schedule tests")
    root = Path(__file__).resolve().parents[1] / "console-ui/src"
    program = r'''
import {SchedulesController} from CONTROLLER;
import {historyText} from MODEL;
const mode = MODE, count = COUNT, c = new SchedulesController(), historyReads = [];
const schedules = Array.from({length: count}, (_, i) => ({id: i === 25 ? 'constructor' : 's' + i,
  rev: 1, etag: '"iris-schedule-' + (i === 25 ? 'constructor' : 's' + i) + '-1"', kind: 'assign', state: 'pending',
  created_by: 'console:operator', creator_exists: true, target: {filters: {}, device_ids: [], bind: 'late'},
  preview: {device_ids: []}, next_fire: null}));
const reply = (body, ok = true) => ({ok, json: async () => body});
c.connect({publishSchedules() {}, fetch: async path => {
  if (path === '/api/v1/schedules') return reply({schedules, total: count});
  historyReads.push(path); if (mode === 'network') throw Error('offline');
  const page = path.includes('offset=');
  if ((mode === 'probe-fails' && !page) || (mode === 'page-fails' && page)) return reply({}, false);
  return reply({total: mode === 'empty' ? 0 : 1, offset: 0,
    occurrences: mode === 'empty' || (mode === 'missing-row' && page) ? [] : [{state: 'completed', schedule_id: path.split('/')[4]}]});
}});
await c.togglePanel();
process.stdout.write(JSON.stringify({rows: c.state.rows.map(row => ({id: row.id, history: historyText(c.state.history.get(row.id))})), historyReads}));
'''.replace("CONTROLLER", json.dumps((root / "schedules-controller.mjs").as_uri())).replace(
        "MODEL", json.dumps((root / "schedules-model.mjs").as_uri())).replace("MODE", json.dumps(mode)).replace("COUNT", str(count))
    result = subprocess.run([node, "--input-type=module", "-"], input=program, text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_history_cap_keeps_unread_schedules_visible_without_claiming_no_runs():
    result = _render("completed", 26)
    assert len(result["rows"]) == 26
    assert len(result["historyReads"]) == 50
    assert result["rows"][-1] == {"id": "constructor", "history": "run history unavailable"}
    assert sum(row["history"] == "completed" for row in result["rows"]) == 25


@pytest.mark.parametrize("mode", ["probe-fails", "page-fails", "network", "missing-row"])
def test_failed_or_incomplete_history_is_unavailable(mode):
    assert _render(mode)["rows"][0]["history"] == "run history unavailable"


def test_confirmed_zero_history_still_reports_no_run_yet():
    result = _render("empty")
    assert result["rows"][0]["history"] == "no run yet"
    assert len(result["historyReads"]) == 1


def test_lost_creation_response_does_not_claim_the_schedule_was_not_created():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for Console schedule tests")
    test = Path(__file__).resolve().parents[1] / "console-ui/tests/schedules.test.mjs"
    result = subprocess.run([node, "--test", "--test-name-pattern", "creation lost", str(test)],
                            text=True, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "# pass 1" in result.stdout
