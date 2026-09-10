# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Execute the Console's job-option projection and batch request path."""
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import shutil
import subprocess

import pytest


_WEBROOT = Path(__file__).resolve().parents[1] / "webroot"


class _CheckboxParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.inputs = {}
        self.labels = {}
        self.label = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "label":
            self.label = {"ids": [], "text": []}
        if tag == "input" and attrs.get("type") == "checkbox" and "id" in attrs:
            self.inputs.setdefault(attrs["id"], []).append(attrs)
            if self.label is not None:
                self.label["ids"].append(attrs["id"])

    def handle_data(self, data):
        if self.label is not None:
            self.label["text"].append(data)

    def handle_endtag(self, tag):
        if tag == "label" and self.label is not None:
            for identity in self.label["ids"]:
                self.labels[identity] = " ".join("".join(self.label["text"]).split())
            self.label = None


def _checkboxes():
    parser = _CheckboxParser()
    parser.feed((_WEBROOT / "index.html").read_text())
    return parser


def _run_js(expression, checked=None, mutate_after_first_post=False):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for Console job-option tests")
    source = (_WEBROOT / "app.js").read_text()
    functions = []
    for name in ("telemetryFlags", "jobFlags", "jpost", "startBatch"):
        match = re.search(
            r"^  (?:async )?function " + name + r"\([^\n]*\) \{.*?^  \}",
            source, re.MULTILINE | re.DOTALL)
        assert match, "Console function missing: " + name
        functions.append(match.group(0))
    program = r"""
const controls = CHECKED;
const elements = Object.fromEntries(
  Object.entries(controls).map(([id, checked]) => [id, { checked }]));
for (const id of ['batch-rows', 'batch-summary', 'batch-panel']) elements[id] = {};
const document = { getElementById: id => elements[id] || null };
const requests = [];
const busy = [];
var outcome = null;
var batchGen = 0;
var batchJobs = {};
function claimSelection() { return ['edge-1', '192.0.2.9']; }
function confirm() { return true; }
function setBulkBusy(value) { busy.push(value); }
function stopBatchPoll() {}
function pollBatch() { return Promise.resolve(false); }
function startBatchPoll() { throw new Error('unexpected poll start'); }
function renderOnboardOutcome(action, started, failed) {
  outcome = { action, started, failed };
}
function csrfHdr(extra) { return extra; }
function fetch(url, options) {
  requests.push({ url, method: options.method, headers: options.headers,
                  body: JSON.parse(options.body) });
  const job = 'job-' + requests.length;
  if (MUTATE && requests.length === 1) {
    for (const control of Object.values(elements)) {
      if ('checked' in control) control.checked = !control.checked;
    }
  }
  return Promise.resolve({ ok: true, json: async () => ({ job_id: job }) });
}
""".replace("CHECKED", json.dumps(checked or {})).replace(
        "MUTATE", json.dumps(mutate_after_first_post))
    program += "\n".join(functions)
    program += "\n(async () => { const result = " + expression + ";\n"
    program += "process.stdout.write(JSON.stringify(result)); })().catch(error => {\n"
    program += "console.error(error); process.exitCode = 1; });\n"
    result = subprocess.run([node, "-"], input=program, text=True,
                            capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_modal_log_checkboxes_are_unchecked_and_labeled():
    parsed = _checkboxes()
    for identity in ("onboard-log", "undeploy-log"):
        assert len(parsed.inputs.get(identity, [])) == 1
        assert "checked" not in parsed.inputs[identity][0]
        assert parsed.labels[identity] == "Detailed logs"


def test_missing_controls_preserve_default_telemetry_and_disable_detailed_logs():
    assert _run_js("({telemetry: telemetryFlags(), onboard: jobFlags('onboard', false), "
                   "undeploy: jobFlags('undeploy', false), forced: jobFlags('undeploy', true)})") == {
        "telemetry": {"telemetry": True, "telemetry_stream": False},
        "onboard": {"telemetry": True, "telemetry_stream": False, "log": False},
        "undeploy": {"log": False},
        "forced": {"force": True, "log": False},
    }


@pytest.mark.parametrize("action", ["onboard", "undeploy"])
@pytest.mark.parametrize("enabled", [False, True])
def test_log_option_reads_only_its_own_modal(action, enabled):
    other = "undeploy" if action == "onboard" else "onboard"
    result = _run_js("jobFlags(%s, false)" % json.dumps(action), {
        action + "-log": enabled, other + "-log": not enabled,
    })
    assert result["log"] is enabled
    assert "force" not in result


@pytest.mark.parametrize("reports", [False, True])
@pytest.mark.parametrize("streaming", [False, True])
def test_onboard_job_flags_preserve_each_telemetry_choice(reports, streaming):
    result = _run_js("({telemetry: telemetryFlags(), job: jobFlags('onboard', true)})", {
        "onboard-telemetry": reports, "onboard-telemetry-stream": streaming,
        "onboard-log": True,
    })
    assert result["telemetry"] == {"telemetry": reports, "telemetry_stream": streaming}
    assert result["job"] == dict(result["telemetry"], log=True)


@pytest.mark.parametrize("action", ["onboard", "undeploy"])
@pytest.mark.parametrize("forced", [False, True])
@pytest.mark.parametrize("enabled", [False, True])
def test_batch_posts_job_options_with_force_and_telemetry_preserved(action, forced, enabled):
    controls = {identity: "checked" in rows[0]
                for identity, rows in _checkboxes().inputs.items()}
    controls.update({action + "-log": enabled, "undeploy-force": forced,
                     "onboard-telemetry": False, "onboard-telemetry-stream": True})
    result = _run_js("(await startBatch(%s), {requests, outcome, busy})" %
                     json.dumps(action), controls)
    expected = {"log": enabled}
    if action == "onboard":
        expected.update(telemetry=False, telemetry_stream=True)
    elif forced:
        expected["force"] = True
    assert len(result["requests"]) == 2
    for identity, request in zip(("edge-1", "192.0.2.9"), result["requests"]):
        assert request == {
            "url": "/api/v1/devices/%s/%s" % (identity, action),
            "method": "POST", "headers": {"Content-Type": "application/json"},
            "body": expected,
        }
    assert result["outcome"] == {"action": action, "started": 2, "failed": []}
    assert result["busy"] == [False]


@pytest.mark.parametrize("action", ["onboard", "undeploy"])
def test_batch_snapshots_options_before_the_first_request(action):
    controls = {"onboard-log": True, "undeploy-log": True, "undeploy-force": True,
                "onboard-telemetry": True, "onboard-telemetry-stream": False}
    result = _run_js("(await startBatch(%s), requests)" % json.dumps(action),
                     controls, mutate_after_first_post=True)
    expected = ({"telemetry": True, "telemetry_stream": False, "log": True}
                if action == "onboard" else {"force": True, "log": True})
    assert [request["body"] for request in result] == [expected, expected]
