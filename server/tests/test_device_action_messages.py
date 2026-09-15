# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import subprocess

import pytest
import device_action_messages as messages
import gui_onboard


@pytest.mark.parametrize("model,series", [
    ("IE-3400-8T2S", "IE Switches"), ("IR1101", "IR Routers"),
    ("C8000V", "Catalyst Routers"), ("C9300-48P", "Catalyst Switches"),
    ("NCS-540", "NCS"), ("8201-SYS", "Cisco 8000 Series"),
])
@pytest.mark.parametrize("action", ["onboard", "undeploy"])
def test_heading_uses_series_not_chassis_or_script(model, series, action):
    assert messages.heading(action, gui_onboard.family(model), "iox") == (
        action.title() + " | " + series + " | IOx")


@pytest.mark.parametrize("platform,total", [
    ("iox", 8), ("xr-appmgr", 5), ("guestshell", 6), ("router", 6),
])
@pytest.mark.parametrize("detailed", [False, True])
def test_onboard_has_three_broad_phases_and_opt_in_details(platform, total, detailed):
    job = {"action": "onboard", "platform": platform,
           "env_extra": {"IRIS_LOG": "on" if detailed else "off"}}
    output = messages.phase(job, 1)
    raw = ["[%s/%s] recipe step" % (step, total) for step in range(1, total + 1)]
    raw += ["  configure_app ok (0.7s)", "app is RUNNING (poll 1/24)"]
    for line in raw:
        output.extend(messages.progress(job, line))
    assert [line for line in output if line.endswith(("onboarding", "IRIS agent"))] == [
        "[1/3] Prepare onboarding", "[2/3] Deploy IRIS agent", "[3/3] Finalize onboarding"]
    for line in raw:
        assert (line in output) is detailed


@pytest.mark.parametrize("platform,total", [
    ("iox", 4), ("xr-appmgr", 5), ("guestshell", 5), ("router", 5),
])
def test_undeploy_has_same_broad_phases(platform, total):
    job = {"action": "undeploy", "platform": platform}
    output = messages.phase(job, 1)
    for step in range(1, total + 1):
        output += messages.progress(job, "[%s/%s] recipe step" % (step, total))
    output += messages.phase(job, 3)
    assert output == ["[1/3] Prepare undeployment", "[2/3] Remove IRIS agent",
                      "[3/3] Finalize undeployment"]


@pytest.mark.parametrize("line", ["ERROR: upload failed", "% Invalid input",
    "  configure_app failed (2.1s)", "PREREQ WARNING: clock wrong",
    "Retry after correcting routing.", "IOx controller: failed (timeout)",
    "[2/5] ERROR: storage check failed"])
def test_errors_and_unknown_diagnostics_never_disappear(line):
    assert messages.progress({"action": "onboard"}, line) == [line]


def test_script_success_does_not_preempt_service_failure():
    assert messages.progress({}, "onboard complete: 192.0.2.1") == []
    assert messages.result("onboard", "error") == "Onboard failed."
    assert messages.result("undeploy", "cancelled") == "Undeploy cancelled."


def test_chassis_details_use_actual_model_and_keep_evidence_source():
    app = (Path(__file__).resolve().parents[1] / "webroot/app.js").read_text()
    fn = app.split("  function deviceHardwareRows", 1)[1].split(
        "  function deployRecordRows", 1)[0]
    program = """
const assert = require('node:assert/strict');
const esc = value => String(value).replaceAll('<','&lt;').replaceAll('>','&gt;');
const deviceSeriesLabel = family => family === 'C8xxx' ? 'Catalyst Routers' : 'NCS';
function deviceHardwareRows""" + fn + """
let html = deviceHardwareRows({model_family:'C8xxx',model:'C8xxx'},
 {preflight:{detected_model:'C8000V'},resolved:{model:'C8xxx'}});
assert.match(html,/Series.*Catalyst Routers/);
assert.match(html,/Chassis model.*C8000V.*last preflight/);
assert.doesNotMatch(html,/Chassis model.*C8xxx/);
assert.match(deviceHardwareRows({model:'NCS'}),/Not detected/);
assert.match(deviceHardwareRows({model:'NCS',heartbeat_model:'NCS-540'}),/NCS-540.*agent-reported/);
assert.match(deviceHardwareRows({model:'NCS',heartbeat_model:'<script>'}),/&lt;script&gt;/);
"""
    result = subprocess.run(["node", "-"], input=program, text=True,
                            capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr
