# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Run the actual option model and both controllers through the CSRF transport."""
import json
from pathlib import Path
import re
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]


def run(action, options, mutate=False):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for Console job-option tests")
    source = (ROOT / "webroot/app.js").read_text()
    post = re.search(r"^  (?:async )?function jpost\([^\n]*\) \{.*?^  \}", source, re.MULTILINE | re.DOTALL)
    assert post, "Missing authenticated job transport"
    modules = ROOT / "console-ui/src"
    imports = "\n".join("import {%s} from %s;" % (name, json.dumps((modules / filename).as_uri())) for name, filename in (
        ("ActivityController", "activity-controller.mjs"), ("InventoryActionsController", "inventory-actions-controller.mjs")))
    script = imports + "\n" + post.group(0) + "\n" + r'''
      const actions = new InventoryActionsController(), requests = [], busy = [];
      let outcome;
      const activity = new ActivityController({setTimer: () => 1, clearTimer() {}}); activity.visible = true;
      function csrfHdr(extra) { return {...extra, 'X-CSRF-Token': 'fixture-csrf'}; }
      async function fetch(url, options) {
        requests.push({url, method: options.method, headers: options.headers, body: JSON.parse(options.body)});
        if (MUTATE && requests.length === 1) actions.update({options: {telemetry: false, telemetry_stream: false, onboardLog: false, undeployLog: false, force: false}});
        return {ok: true, json: async () => ({job_id: 'job-' + requests.length})};
      }
      activity.connect({post: jpost, confirm: () => true,
        fetch: async () => ({ok: true, json: async () => ({jobs: [], now: 1000})}),
        outcome: (message, failed) => { outcome = {message, failed}; }});
      actions.connect({claimBulk: () => {busy.push(true); return true;}, releaseBulk: () => busy.push(false),
        startJobs: (...args) => activity.start(...args)});
      actions.open(ACTION, ['edge-1', '192.0.2.9']);
      for (const [key, value] of Object.entries(OPTIONS)) actions.option(key, value);
      await actions.start();
      console.log(JSON.stringify({requests, outcome, busy, activityVisible: activity.state.open}));
      activity.dispose();
    '''.replace("MUTATE", json.dumps(mutate)).replace("ACTION", json.dumps(action)).replace("OPTIONS", json.dumps(options))
    result = subprocess.run([node, "--input-type=module", "-"], input=script, text=True,
                            capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize("action", ["onboard", "undeploy"])
@pytest.mark.parametrize("forced", [False, True])
@pytest.mark.parametrize("enabled", [False, True])
def test_batch_posts_only_its_own_options_with_csrf(action, forced, enabled):
    result = run(action, {"telemetry": False, "telemetry_stream": True, "force": forced,
                          "onboardLog": enabled if action == "onboard" else not enabled,
                          "undeployLog": enabled if action == "undeploy" else not enabled})
    expected = {"log": enabled}
    if action == "onboard":
        expected.update(telemetry=False, telemetry_stream=True)
    elif forced:
        expected["force"] = True
    assert [row["body"] for row in result["requests"]] == [expected, expected]
    for identity, request in zip(("edge-1", "192.0.2.9"), result["requests"]):
        assert request["url"] == "/api/v1/devices/%s/%s" % (identity, action)
        assert request["method"] == "POST"
        assert request["headers"] == {"Content-Type": "application/json", "X-CSRF-Token": "fixture-csrf"}
    assert result["outcome"] == {"message": "Started %s for 2 device(s)" % action, "failed": False}
    assert result["busy"] == [True, False]
    assert result["activityVisible"] is True


@pytest.mark.parametrize("action", ["onboard", "undeploy"])
def test_job_defaults_and_snapshot_survive_controls_changing_mid_batch(action):
    result = run(action, {}, mutate=True)
    expected = {"telemetry": True, "telemetry_stream": False, "log": False} if action == "onboard" else {"log": False}
    assert [row["body"] for row in result["requests"]] == [expected, expected]
    result = run(action, {"onboardLog": True, "undeployLog": True, "force": True}, mutate=True)
    expected = {"telemetry": True, "telemetry_stream": False, "log": True} if action == "onboard" else {"force": True, "log": True}
    assert [row["body"] for row in result["requests"]] == [expected, expected]
